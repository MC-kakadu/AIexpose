package checks

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/MC-kakadu/AIexpose/internal/hashdb"
	"github.com/MC-kakadu/AIexpose/internal/model"
	"github.com/MC-kakadu/AIexpose/internal/supply"
)

// malwareIndex is an opened hash index plus the reason there isn't one.
type malwareIndex struct {
	db  *hashdb.DB
	err error
}

func (m malwareIndex) available() bool { return m.db != nil }

// corpus names the corpus in the form a finding's prose needs.
func (m malwareIndex) corpus() string {
	if m.db == nil {
		return "a local malware hash corpus"
	}
	meta := m.db.Meta()
	source := meta.Source
	if source == "" {
		source = "a local malware hash corpus"
	}
	return fmt.Sprintf("%s (%s hashes, %s)", source, thousands(m.db.Count()), builtLabel(meta))
}

// label describes the corpus in one line, for the report's attestation.
func (m malwareIndex) label() string {
	if m.db == nil {
		return ""
	}
	meta := m.db.Meta()
	source := meta.Source
	if source == "" {
		source = "local malware hash corpus"
	}
	return fmt.Sprintf("%s, %s hashes, %s", source, thousands(m.db.Count()), builtLabel(meta))
}

func (m malwareIndex) close() {
	if m.db != nil {
		_ = m.db.Close()
	}
}

// openMalwareIndex opens the local malware-hash index, if one has been built.
// It is opened before the inventory is taken, because its presence decides
// whether the inventory pays to hash binaries at all.
func openMalwareIndex(path string, disabled bool) malwareIndex {
	if disabled {
		return malwareIndex{}
	}
	if path == "" {
		path = hashdb.DefaultPath()
	}
	db, err := hashdb.Open(path)
	if err != nil {
		return malwareIndex{err: err}
	}
	return malwareIndex{db: db}
}

// reportMalwareHashes checks every file hashed during the inventory against the
// local malware corpus.
//
// What this catches and what it does not is worth being precise about. The
// corpus is a general malware collection -- overwhelmingly Windows executables
// -- so it will recognise a commodity stealer or miner that ended up inside an
// AI tool's directory. It will not recognise a backdoored MCP package or a
// ComfyUI node that reads browser password stores, because those are Python
// source that no antivirus corpus has ever indexed. That is what the curated
// known-bad list and the source indicators are for. The three layers overlap
// very little, which is the reason to run all of them.
// weightHashLimit caps how large a model file may be before hashing it costs
// more than the answer is worth. A 3 GB checkpoint takes seconds to read and no
// public malware corpus indexes one.
const weightHashLimit = 64 << 20

// minHashSize is the floor below which a hash match means nothing.
//
// This is not a tuning knob, it is a correctness requirement for this data
// source. VirusShare is a collection of submitted samples, and trivial files
// end up in it -- the empty file's MD5, d41d8cd98f00b204e9800998ecf8427e, is in
// the corpus. Any scan that hashes a zero-byte file therefore "matches known
// malware", and a machine full of empty marker files gets told it is
// compromised. No real sample is 64 bytes long; nothing under that is worth
// comparing.
const minHashSize = 64

// oneMatch groups every file that hashed to the same value. Reporting three
// separate criticals for three files with one hash buries the fact that it is
// one hash, which is exactly the signal that says "this is a degenerate file,
// not three infections".
type oneMatch struct {
	sum     [16]byte
	entries []string
	first   string // a label for the thing the first match was found in
	single  bool   // the label names one file rather than a component
	ids     []string
}

func reportMalwareHashes(r *model.Report, inv supply.Inventory, weights ModelInventory, idx malwareIndex, disabled, hashAll bool) {
	if disabled {
		r.Note("Malware hash matching skipped (--no-hashdb).")
		return
	}
	if !idx.available() {
		reportNoIndex(r, idx.err)
		return
	}

	var order [][16]byte
	matches := map[[16]byte]*oneMatch{}
	record := func(sum [16]byte, entry, label string, single bool, id string) {
		m, ok := matches[sum]
		if !ok {
			m = &oneMatch{sum: sum, first: label, single: single}
			matches[sum] = m
			order = append(order, sum)
		}
		m.entries = append(m.entries, entry)
		if id != "" {
			m.ids = append(m.ids, id)
		}
	}

	checked, tooSmall := 0, 0
	fail := func(err error) {
		r.Note("The malware hash index became unreadable partway through: " + err.Error())
	}

	// Components first: source and compiled files inside the AI stack.
	for _, a := range inv.Artifacts {
		for _, fh := range a.Hashes {
			if fh.Size < minHashSize {
				tooSmall++
				continue
			}
			checked++
			ok, err := idx.db.Contains(fh.Sum)
			if err != nil {
				fail(err)
				return
			}
			if ok {
				record(fh.Sum, a.Path+string(filepath.Separator)+fh.Rel,
					kindLabel(a.Kind)+" "+strconv.Quote(a.Name), false, a.ID)
			}
		}
	}

	// Then the model files the format walk already found. On a machine whose
	// AI stack is just a model runner, these are the only files there are.
	limit := int64(weightHashLimit)
	if hashAll {
		limit = 1 << 62
	}
	oversize := 0
	for _, w := range weights.Files {
		switch {
		case w.Size < 0 || w.Size > limit:
			oversize++
			continue
		case w.Size < minHashSize:
			tooSmall++
			continue
		}
		sum, err := fileMD5(w.Path)
		if err != nil {
			continue
		}
		checked++
		ok, err := idx.db.Contains(sum)
		if err != nil {
			fail(err)
			return
		}
		if ok {
			record(sum, w.Path, "Model file "+strconv.Quote(filepath.Base(w.Path)), true, "")
		}
	}

	corpus := idx.corpus()

	for _, sum := range order {
		m := matches[sum]
		title := m.first + " matches a known-malware hash"
		if !m.single {
			title = m.first + " contains a file that matches a known-malware hash"
		}
		if len(m.entries) > 1 {
			title = fmt.Sprintf("%d files match the same known-malware hash", len(m.entries))
		}
		sort.Strings(m.entries)
		f := model.Finding{
			ID:       "SUP-050",
			Title:    title,
			Severity: model.Critical,
			Detail: "These contents hash to a value that appears in " + corpus + ". " +
				"Every hash in that corpus belongs to a sample that was collected as malware, so this file is " +
				"byte-for-byte identical to something already identified as hostile.\n" +
				"MD5: " + hex.EncodeToString(sum[:]) + "\nMatched against: " + idx.db.Path(),
			Evidence: m.entries,
			Fix: "Stop the tool that loads this file and delete it, then the component around it. " +
				"Run a full scan with your antivirus. Treat every credential that was reachable from this machine as exposed: " +
				"browser-saved passwords, API keys, SSH keys and wallet seeds.",
		}
		f.Artifacts = m.ids
		r.Add(f)
	}
	if len(order) > 0 {
		return
	}

	// Nothing matched. Whether that is a result depends entirely on whether
	// anything was actually hashed -- and on a machine running only a model
	// server, nothing is. Reporting "no match" against zero files is the same
	// false pass this scanner already had to fix once for empty lists.
	if checked == 0 {
		r.Add(model.Finding{
			ID:       "SUP-053",
			Title:    "The malware hash index had nothing to check",
			Severity: model.Info,
			NotRun:   true,
			Detail: "The index is installed and holds " + corpus + ", but no file on this machine was of a kind it can " +
				"usefully be compared against, so this check produced no result at all -- not a pass.\n\n" +
				"It hashes the source and compiled files inside ComfyUI custom nodes, MCP servers and agent skills, " +
				"and model files under " + humanSize(weightHashLimit) + ". " + skippedNote(oversize, tooSmall, hashAll) +
				"Model weights larger than that are excluded deliberately: they take seconds each to read, and a general " +
				"malware corpus does not contain them.\n\n" +
				"If your AI stack is a model runner and nothing else, this check has nothing to bite on. That is the " +
				"honest answer, and it is worth knowing before you keep a " + indexSize(idx) + " index on disk for it.",
		})
		return
	}

	r.Add(model.Finding{
		ID:       "SUP-052",
		Title:    fmt.Sprintf("No installed file matches a known-malware hash (%d file(s) checked)", checked),
		Severity: model.Info,
		Detail: strings.TrimSpace("Checked against "+corpus+". "+skippedNote(oversize, tooSmall, hashAll)) + "\n" +
			"This corpus is general malware, not an AI-specific threat list. It recognises a commodity " +
			"stealer or miner sitting inside an AI tool's directory; it does not recognise a backdoored " +
			"MCP package or a malicious ComfyUI node, because those are source code that no malware " +
			"corpus indexes. The known-bad component list and the source inspection above cover that case.",
	})
}

// skippedNote states how many files were passed over and why, because a count
// of what was checked means little without it.
func skippedNote(oversize, tooSmall int, hashAll bool) string {
	var parts []string
	if oversize > 0 {
		part := fmt.Sprintf("%d file(s) were skipped for being larger than %s",
			oversize, humanSize(weightHashLimit))
		if !hashAll {
			part += " (--hash-all reads them too, at several seconds per gigabyte)"
		}
		parts = append(parts, part)
	}
	if tooSmall > 0 {
		parts = append(parts, fmt.Sprintf("%d were skipped for being under %d bytes, "+
			"a size at which a hash match carries no information", tooSmall, minHashSize))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, ", and ") + ". "
}

func indexSize(idx malwareIndex) string {
	if st, err := os.Stat(idx.db.Path()); err == nil {
		return humanSize(st.Size())
	}
	return "large"
}

// fileMD5 hashes a file in full. A partial hash matches nothing in a corpus.
func fileMD5(path string) ([16]byte, error) {
	var sum [16]byte
	f, err := os.Open(path)
	if err != nil {
		return sum, err
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return sum, err
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

// reportNoIndex explains the feature to someone who has never built the index,
// which is everyone on a first run. It is Info and not Advisory on purpose:
// this is an optional local add-on, and marking the whole report incomplete
// because an opt-in extra is absent would make the badge meaningless.
func reportNoIndex(r *model.Report, err error) {
	if err != nil && !errors.Is(err, hashdb.ErrNotBuilt) {
		r.Add(model.Finding{
			ID:       "SUP-051",
			Title:    "The malware hash index could not be read",
			Severity: model.Low,
			Detail: "An index file exists but this scan could not use it, so no file was checked against " +
				"a malware corpus. Everything else in this report still ran.\n" + err.Error(),
			Fix:     "Build it again from the hash lists you downloaded:",
			Command: buildHashDBCommand(),
		})
		return
	}
	r.Add(model.Finding{
		ID:       "SUP-051",
		Title:    "No local malware hash index is installed",
		Severity: model.Info,
		NotRun:   true,
		Detail: "This scan can compare every file in your AI stack against a corpus of known malware " +
			"hashes, entirely offline. No index is installed, so it did not.\n\n" +
			"There are two ways to get one, and either is a one-off.\n\n" +
			"The quicker way: download aiexpose-hashdb.bin and the two small files published beside it " +
			"from the project's releases page, then run the command below. The signature and digest are " +
			"checked before anything is installed, so an altered index is refused rather than trusted. " +
			"The download is roughly 255 MB.\n\n" +
			"The independent way: download the MD5 lists from VirusShare.com yourself, put them in a " +
			"folder, and build the index with --build-hashdb. It takes about a minute, reads about " +
			"1.5 GB and trusts nobody's copy but your own.\n\n" +
			"Either way the result is one file of roughly 255 MB in " + hashdb.DefaultPath() +
			". Scans after that read it directly; nothing is sent anywhere.\n\n" +
			"Worth knowing before you spend the disk: that corpus is general malware, mostly Windows " +
			"executables. It catches a commodity stealer that ended up in an AI tool's folder. It does " +
			"not catch a backdoored MCP package or a malicious ComfyUI node -- those are Python source, " +
			"and the known-bad list and source inspection in this report are what cover them.",
		Fix:     "Install a downloaded index (or use --build-hashdb to build your own):",
		Command: installHashDBCommand(),
	})
}

// installHashDBCommand is the one-off that verifies and installs a downloaded
// corpus. It names the file the releases page publishes, so the reader can
// match what they downloaded against what the command expects.
func installHashDBCommand() string {
	return selfCommand("--install-hashdb aiexpose-hashdb.bin")
}

// buildHashDBCommand is the one-off that builds the corpus from source lists.
func buildHashDBCommand() string {
	dir := "./virusHashDb"
	if runtime.GOOS == "windows" {
		dir = "virusHashDb"
	}
	return selfCommand("--build-hashdb " + dir)
}

func builtLabel(m hashdb.Meta) string {
	if m.Built.IsZero() {
		return "built locally"
	}
	return "built " + m.Built.Local().Format("2006-01-02")
}

// thousands groups a count so a nine-figure number is readable at a glance.
func thousands(n int) string {
	s := fmt.Sprint(n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}
