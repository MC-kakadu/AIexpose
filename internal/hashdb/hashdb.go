// Package hashdb answers one question, offline and in microseconds: has this
// exact file been seen before in a public malware corpus?
//
// The corpus this is built for is VirusShare's MD5 list -- roughly 42 million
// hashes spread over 500 text files, about 1.5 GB of ASCII. That is far too
// much to embed in an executable and too much to hold in memory during a scan,
// so it is compiled once into a sorted binary index that a scan reads with a
// single seek per lookup.
//
// Two design decisions are worth stating plainly.
//
// The index stores a 64-bit prefix of each MD5 rather than the whole thing.
// That makes the file 255 MB instead of 680 MB and lets a lookup compare
// integers. A prefix match is therefore not proof: with 42 million entries the
// chance that an unrelated file collides is about 1 in 400 billion per lookup.
// Across every file this tool will ever hash that is still expected to happen
// approximately never, but the report says "matches a known-malware hash"
// rather than "is malware", because that is what was actually established.
//
// The corpus is general Windows malware. It is not an AI-specific threat list,
// and the overlap with the things this scanner exists to catch -- a backdoored
// MCP package, a ComfyUI node that reads browser password stores -- is close to
// zero. This check complements the curated known-bad list; it does not replace
// it. See STATUS.md for why both exist.
package hashdb

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	// magicStr identifies the format and its version. A future format change
	// bumps the last byte, and an old index is then rejected rather than
	// misread.
	magicStr = "AIXMD5\x01\x00"

	bucketBits  = 16
	bucketCount = 1 << bucketBits // top two bytes of the MD5 select a bucket
	entryBytes  = 6               // the remaining 48 bits of the 64-bit prefix
	mask48      = 1<<48 - 1

	headerBytes = 24                    // magic(8) count(4) bucketBits(4) entryBytes(4) reserved(4)
	offsetBytes = (bucketCount + 1) * 4 // cumulative entry index per bucket
	entriesAt   = headerBytes + offsetBytes
)

// ErrNotBuilt means no index exists yet. It is an ordinary state, not a
// failure: the index is large and every user has to build it deliberately.
var ErrNotBuilt = errors.New("no malware hash index has been built yet")

// Meta records where an index came from, so a report can say what it matched
// against instead of asserting an anonymous verdict.
type Meta struct {
	Source      string    `json:"source"` // human label, e.g. "VirusShare MD5 lists"
	SourceDir   string    `json:"source_dir"`
	SourceFiles int       `json:"source_files"`
	Hashes      int       `json:"hashes"`
	Built       time.Time `json:"built"`
	Tool        string    `json:"tool"`
}

// DefaultPath is where a scan looks for the index.
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "hashdb.bin"
	}
	return filepath.Join(home, ".aiexpose", "hashdb.bin")
}

func metaPath(indexPath string) string {
	return strings.TrimSuffix(indexPath, filepath.Ext(indexPath)) + ".meta.json"
}

// --- lookup -------------------------------------------------------------

// DB is an open index. It holds the bucket offset table in memory (256 KB) and
// reads the entries themselves from disk, one small range per lookup.
type DB struct {
	f       *os.File
	offsets []uint32
	count   uint32
	meta    Meta
	path    string
}

// Open maps an existing index. It returns ErrNotBuilt when there is none,
// which callers are expected to treat as "this check is unavailable" rather
// than as an error.
func Open(path string) (*DB, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotBuilt
	}
	if err != nil {
		return nil, err
	}

	head := make([]byte, headerBytes)
	if _, err := readFullAt(f, head, 0); err != nil {
		f.Close()
		return nil, fmt.Errorf("index header is unreadable: %w", err)
	}
	if string(head[:8]) != magicStr {
		f.Close()
		return nil, errors.New("this file is not an aiexpose hash index, or was built by a different version")
	}
	count := binary.LittleEndian.Uint32(head[8:12])
	if b := binary.LittleEndian.Uint32(head[12:16]); b != bucketBits {
		f.Close()
		return nil, fmt.Errorf("index uses %d bucket bits, this build expects %d", b, bucketBits)
	}
	if e := binary.LittleEndian.Uint32(head[16:20]); e != entryBytes {
		f.Close()
		return nil, fmt.Errorf("index uses %d-byte entries, this build expects %d", e, entryBytes)
	}

	raw := make([]byte, offsetBytes)
	if _, err := readFullAt(f, raw, headerBytes); err != nil {
		f.Close()
		return nil, fmt.Errorf("index offset table is unreadable: %w", err)
	}
	offsets := make([]uint32, bucketCount+1)
	for i := range offsets {
		offsets[i] = binary.LittleEndian.Uint32(raw[i*4:])
	}
	if offsets[bucketCount] != count {
		f.Close()
		return nil, errors.New("index offset table does not agree with its own entry count; rebuild it")
	}

	// The file must be exactly as long as its header claims. A truncated index
	// would otherwise silently answer "no" for everything after the cut.
	st, err := f.Stat()
	if err == nil && st.Size() != int64(entriesAt)+int64(count)*entryBytes {
		f.Close()
		return nil, errors.New("index is truncated or has trailing data; rebuild it")
	}

	db := &DB{f: f, offsets: offsets, count: count, path: path}
	if b, err := os.ReadFile(metaPath(path)); err == nil {
		_ = json.Unmarshal(b, &db.meta)
	}
	return db, nil
}

func (db *DB) Close() error { return db.f.Close() }

// Count is how many distinct hashes the index holds.
func (db *DB) Count() int { return int(db.count) }

// Meta describes the corpus this index was built from.
func (db *DB) Meta() Meta { return db.meta }

// Path is where the index lives on disk.
func (db *DB) Path() string { return db.path }

// Contains reports whether the corpus holds a hash with this 64-bit prefix.
// See the package comment on why a true answer is very strong evidence rather
// than proof.
func (db *DB) Contains(sum [16]byte) (bool, error) {
	key := binary.BigEndian.Uint64(sum[:8])
	bucket := key >> (64 - bucketBits)
	tail := key & mask48

	lo, hi := db.offsets[bucket], db.offsets[bucket+1]
	if lo >= hi {
		return false, nil
	}
	n := int(hi - lo)
	buf := make([]byte, n*entryBytes)
	if _, err := readFullAt(db.f, buf, int64(entriesAt)+int64(lo)*entryBytes); err != nil {
		return false, err
	}
	i := sort.Search(n, func(i int) bool { return read48(buf[i*entryBytes:]) >= tail })
	return i < n && read48(buf[i*entryBytes:]) == tail, nil
}

func readFullAt(f *os.File, b []byte, off int64) (int, error) {
	read := 0
	for read < len(b) {
		n, err := f.ReadAt(b[read:], off+int64(read))
		read += n
		if err != nil {
			return read, err
		}
	}
	return read, nil
}

func read48(b []byte) uint64 {
	return uint64(b[0])<<40 | uint64(b[1])<<32 | uint64(b[2])<<24 |
		uint64(b[3])<<16 | uint64(b[4])<<8 | uint64(b[5])
}

func put48(b []byte, v uint64) {
	b[0] = byte(v >> 40)
	b[1] = byte(v >> 32)
	b[2] = byte(v >> 24)
	b[3] = byte(v >> 16)
	b[4] = byte(v >> 8)
	b[5] = byte(v)
}

// --- build --------------------------------------------------------------

// BuildStats is what the build command prints when it finishes.
type BuildStats struct {
	SourceFiles int
	LinesRead   int
	Hashes      int
	Duplicates  int
	IndexBytes  int64
	Elapsed     time.Duration
	Path        string
}

// SourceFiles lists the VirusShare hash lists in a directory. Downloads carry
// either extension depending on when they were fetched, so both are accepted.
func SourceFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if strings.HasSuffix(name, ".md5") || strings.HasSuffix(name, ".md5.txt") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out, nil
}

// Build compiles a directory of hash lists into a single sorted index.
//
// It holds one uint64 per hash while sorting, so peak memory is roughly 8
// bytes times the number of hashes -- about 340 MB for the full VirusShare
// set. That is the price of doing this once instead of on every scan.
func Build(srcDir, outPath string, progress func(done, total int, name string)) (BuildStats, error) {
	start := time.Now()
	var stats BuildStats
	stats.Path = outPath

	files, err := SourceFiles(srcDir)
	if err != nil {
		return stats, fmt.Errorf("hash list directory could not be read: %w", err)
	}
	if len(files) == 0 {
		return stats, fmt.Errorf("no .md5 or .md5.txt files in %s", srcDir)
	}
	stats.SourceFiles = len(files)

	// Pre-size the slice from the total byte count. VirusShare lines are a
	// 32-character hash plus a newline, so this over-estimates only by the
	// handful of header lines per file and avoids repeated regrowth of a
	// 340 MB slice.
	var totalBytes int64
	for _, p := range files {
		if st, err := os.Stat(p); err == nil {
			totalBytes += st.Size()
		}
	}
	keys := make([]uint64, 0, totalBytes/33+1024)

	for i, p := range files {
		if progress != nil {
			progress(i, len(files), filepath.Base(p))
		}
		n, read, err := appendFile(&keys, p)
		if err != nil {
			return stats, err
		}
		stats.LinesRead += read
		_ = n
	}
	if progress != nil {
		progress(len(files), len(files), "sorting")
	}

	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	// Deduplicate in place. Samples repeat across VirusShare archives, and two
	// copies of the same hash would only widen a bucket.
	out := keys[:0]
	var prev uint64
	for i, k := range keys {
		if i > 0 && k == prev {
			stats.Duplicates++
			continue
		}
		out = append(out, k)
		prev = k
	}
	keys = out
	stats.Hashes = len(keys)

	if progress != nil {
		progress(len(files), len(files), "writing index")
	}
	if err := writeIndex(outPath, keys); err != nil {
		return stats, err
	}
	if st, err := os.Stat(outPath); err == nil {
		stats.IndexBytes = st.Size()
	}

	meta := Meta{
		Source: "VirusShare MD5 lists", SourceDir: srcDir,
		SourceFiles: len(files), Hashes: len(keys),
		Built: time.Now().UTC(), Tool: "aiexpose",
	}
	if b, err := json.MarshalIndent(meta, "", "  "); err == nil {
		_ = os.WriteFile(metaPath(outPath), append(b, '\n'), 0o600)
	}

	stats.Elapsed = time.Since(start).Round(time.Millisecond)
	return stats, nil
}

// appendFile parses one hash list. Anything that is not a 32-character hex
// string is skipped, which covers the '#' banner every VirusShare file opens
// with as well as blank lines and stray whitespace.
func appendFile(keys *[]uint64, path string) (added, lines int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, fmt.Errorf("hash list %s could not be read: %w", filepath.Base(path), err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		lines++
		line := trimLine(sc.Bytes())
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		k, ok := parsePrefix(line)
		if !ok {
			continue
		}
		*keys = append(*keys, k)
		added++
	}
	if err := sc.Err(); err != nil {
		return added, lines, fmt.Errorf("hash list %s ended badly: %w", filepath.Base(path), err)
	}
	return added, lines, nil
}

func trimLine(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\r' || b[len(b)-1] == ' ' || b[len(b)-1] == '\t') {
		b = b[:len(b)-1]
	}
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t') {
		b = b[1:]
	}
	return b
}

// parsePrefix reads the first 16 hex characters of a 32-character MD5 into a
// uint64. The remaining 16 are validated but discarded; see the package
// comment on why the index is a prefix.
func parsePrefix(line []byte) (uint64, bool) {
	if len(line) != 32 {
		return 0, false
	}
	var v uint64
	for i := 0; i < 32; i++ {
		var d uint64
		switch c := line[i]; {
		case c >= '0' && c <= '9':
			d = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint64(c-'A') + 10
		default:
			return 0, false
		}
		if i < 16 {
			v = v<<4 | d
		}
	}
	return v, true
}

// writeIndex lays out header, bucket offsets and entries, then renames into
// place so an interrupted build never leaves a half-written index behind.
func writeIndex(path string, keys []uint64) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("index directory could not be created: %w", err)
		}
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("index could not be written: %w", err)
	}
	defer os.Remove(tmp)

	w := bufio.NewWriterSize(f, 1<<20)

	head := make([]byte, headerBytes)
	copy(head, magicStr)
	binary.LittleEndian.PutUint32(head[8:], uint32(len(keys)))
	binary.LittleEndian.PutUint32(head[12:], bucketBits)
	binary.LittleEndian.PutUint32(head[16:], entryBytes)
	if _, err := w.Write(head); err != nil {
		f.Close()
		return err
	}

	// keys is sorted, so the start of each bucket is found in one pass.
	offsets := make([]byte, offsetBytes)
	next := 0
	for b := 0; b <= bucketCount; b++ {
		for next < len(keys) && int(keys[next]>>(64-bucketBits)) < b {
			next++
		}
		binary.LittleEndian.PutUint32(offsets[b*4:], uint32(next))
	}
	if _, err := w.Write(offsets); err != nil {
		f.Close()
		return err
	}

	entry := make([]byte, entryBytes)
	for _, k := range keys {
		put48(entry, k&mask48)
		if _, err := w.Write(entry); err != nil {
			f.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("index could not be moved into place: %w", err)
	}
	return nil
}
