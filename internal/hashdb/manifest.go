package hashdb

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The index is roughly 255 MB, which is why it is distributed as a release
// asset rather than committed to the repository: GitHub refuses any file over
// 100 MiB, and the corpus cannot be compressed below that without raising the
// false-positive rate to the point where the scanner would start accusing
// clean files. Forty-two million random 64-bit prefixes need about forty bits
// each however they are encoded; that is arithmetic, not an implementation we
// have not got round to writing.
//
// A downloaded index is a trust-critical input for exactly the reason the feed
// is: whoever controls it controls which files this tool calls malware, and --
// more quietly -- which files it stays silent about. So it is verified before
// it is installed. Ed25519 signs a small manifest rather than the index
// itself, so neither the signer nor this tool has to hold a quarter of a
// gigabyte in memory to check it; the manifest carries the index's SHA-256 and
// the chain of trust runs from the compiled-in public key through the manifest
// to the bytes on disk.

// ManifestFormat is the manifest schema version. A future change bumps it and
// an older tool refuses the file instead of misreading it.
const ManifestFormat = "aiexpose-hashdb-manifest/1"

// Manifest describes one published index.
type Manifest struct {
	Format string `json:"format"`
	// SHA256 is the hex digest of the index file the manifest describes.
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	// Index is the expected file name, recorded so a mismatched pairing is
	// visible in the error rather than silently accepted.
	Index string `json:"index"`
	Meta  Meta   `json:"meta"`
}

// ManifestPath is where the manifest for an index is expected to sit.
func ManifestPath(indexPath string) string {
	return strings.TrimSuffix(indexPath, filepath.Ext(indexPath)) + ".manifest.json"
}

// ErrManifestMissing means the index arrived without the manifest that vouches
// for it. This is an ordinary mistake -- downloading one file of three -- and
// the caller is expected to say so plainly rather than treat it as corruption.
var ErrManifestMissing = errors.New("no manifest beside the index")

// ErrDigestMismatch means the file on disk is not the file that was signed.
var ErrDigestMismatch = errors.New("the index does not match the digest in its manifest")

// FileDigest streams the SHA-256 of a file. The index is far too large to read
// into memory, and there is no reason to: the digest is computed in one pass.
func FileDigest(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// WriteManifest records what an index is, for a maintainer to sign. It is a
// release step, not something a scan ever does.
func WriteManifest(indexPath, manifestPath string) (Manifest, error) {
	db, err := Open(indexPath)
	if err != nil {
		return Manifest{}, fmt.Errorf("the index could not be read: %w", err)
	}
	meta := db.Meta()
	count := db.Count()
	db.Close()

	// An index whose meta.json went missing would otherwise be published with
	// an empty provenance, and every report built on it would say only that it
	// matched "a local malware hash corpus".
	if meta.Source == "" {
		return Manifest{}, errors.New("the index has no meta.json beside it, so its provenance cannot be published")
	}
	if meta.Hashes == 0 {
		meta.Hashes = count
	}

	sum, size, err := FileDigest(indexPath)
	if err != nil {
		return Manifest{}, err
	}
	m := Manifest{
		Format: ManifestFormat,
		SHA256: sum,
		Bytes:  size,
		Index:  filepath.Base(indexPath),
		Meta:   meta,
	}
	if manifestPath == "" {
		manifestPath = ManifestPath(indexPath)
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	return m, os.WriteFile(manifestPath, append(b, '\n'), 0o644)
}

// ReadManifest loads and verifies a manifest for an index.
//
// verify is the signature check, passed in rather than imported so this
// package keeps no dependency on the feed. A nil verify is refused rather than
// quietly skipped: an unverified manifest is worth nothing, and a caller that
// forgot to pass one should find out here and not in the field.
func ReadManifest(indexPath string, verify func(doc, sig []byte) error) (Manifest, error) {
	if verify == nil {
		return Manifest{}, errors.New("no signature check was supplied, so the manifest cannot be trusted")
	}
	mp := ManifestPath(indexPath)
	doc, err := os.ReadFile(mp)
	if errors.Is(err, os.ErrNotExist) {
		return Manifest{}, fmt.Errorf("%w: expected %s", ErrManifestMissing, filepath.Base(mp))
	}
	if err != nil {
		return Manifest{}, err
	}
	sig, err := os.ReadFile(mp + ".sig")
	if errors.Is(err, os.ErrNotExist) {
		return Manifest{}, fmt.Errorf("%w: expected %s", ErrManifestMissing, filepath.Base(mp)+".sig")
	}
	if err != nil {
		return Manifest{}, err
	}
	if err := verify(doc, sig); err != nil {
		return Manifest{}, fmt.Errorf("the manifest's signature was rejected: %w", err)
	}

	var m Manifest
	if err := json.Unmarshal(doc, &m); err != nil {
		return Manifest{}, fmt.Errorf("the manifest is not readable: %w", err)
	}
	if m.Format != ManifestFormat {
		return Manifest{}, fmt.Errorf("the manifest is format %q, this build expects %q", m.Format, ManifestFormat)
	}
	if len(m.SHA256) != 64 {
		return Manifest{}, errors.New("the manifest carries no usable digest")
	}
	return m, nil
}

// Verify checks an index file against a verified manifest.
func (m Manifest) Verify(indexPath string) error {
	sum, size, err := FileDigest(indexPath)
	if err != nil {
		return err
	}
	if size != m.Bytes {
		return fmt.Errorf("%w: it is %d bytes, the manifest says %d", ErrDigestMismatch, size, m.Bytes)
	}
	if !strings.EqualFold(sum, m.SHA256) {
		return ErrDigestMismatch
	}
	return nil
}

// Install verifies a downloaded index and puts it where every later scan
// looks, along with the provenance the report will quote.
//
// Nothing is downloaded here. The user fetches the three files with a browser
// and points this at them; the tool's job is to refuse anything that does not
// verify, which is the whole reason this command exists rather than an
// instruction to copy a file into place by hand.
func Install(srcIndex, destPath string, verify func(doc, sig []byte) error) (Manifest, error) {
	m, err := ReadManifest(srcIndex, verify)
	if err != nil {
		return Manifest{}, err
	}
	if want, got := m.Index, filepath.Base(srcIndex); want != "" && want != got {
		return Manifest{}, fmt.Errorf("the manifest describes %q but this file is %q; they are not a pair", want, got)
	}
	if err := m.Verify(srcIndex); err != nil {
		return Manifest{}, err
	}
	// Opening it proves the format is one this build can read, so a bad
	// download is refused now rather than at the start of the next scan.
	db, err := Open(srcIndex)
	if err != nil {
		return Manifest{}, fmt.Errorf("the index verified but could not be opened: %w", err)
	}
	count := db.Count()
	db.Close()

	if destPath == "" {
		destPath = DefaultPath()
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0o700); err != nil {
		return Manifest{}, fmt.Errorf("the index verified but could not be stored: %w", err)
	}
	if err := copyFile(srcIndex, destPath); err != nil {
		return Manifest{}, fmt.Errorf("the index verified but could not be stored: %w", err)
	}

	meta := m.Meta
	if meta.Hashes == 0 {
		meta.Hashes = count
	}
	if meta.Built.IsZero() {
		meta.Built = time.Now().UTC()
	}
	b, err := json.MarshalIndent(meta, "", "  ")
	if err == nil {
		err = os.WriteFile(metaPath(destPath), append(b, '\n'), 0o600)
	}
	if err != nil {
		// The index is usable; only its provenance is missing. Say so rather
		// than failing an install that actually worked.
		return m, fmt.Errorf("the index was installed but its provenance could not be stored: %w", err)
	}
	return m, nil
}

// copyFile writes through a temporary file in the destination directory, so an
// interrupted install never leaves a half-written index that the next scan
// would open and read as a complete one.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp, err := os.CreateTemp(filepath.Dir(dst), ".hashdb-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpName, dst)
}
