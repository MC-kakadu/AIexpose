package hashdb

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// virusShareFile writes a hash list shaped exactly like a real download: a
// banner of '#' lines, then one lowercase 32-character hash per line.
func virusShareFile(t *testing.T, path string, hashes []string) {
	t.Helper()
	body := "################################\n" +
		"# Malware sample MD5 list for   #\n" +
		"# VirusShare_00000.zip          #\n" +
		"# http://VirusShare.com         #\n" +
		"################################\n"
	for _, h := range hashes {
		body += h + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func sumOf(s string) [16]byte { return md5.Sum([]byte(s)) }

func hexOf(s string) string {
	b := sumOf(s)
	return hex.EncodeToString(b[:])
}

func buildFixture(t *testing.T, known []string) (*DB, string) {
	t.Helper()
	src := t.TempDir()

	// Split across two files and two extensions, because a real download
	// directory has both.
	var a, b []string
	for i, s := range known {
		if i%2 == 0 {
			a = append(a, hexOf(s))
		} else {
			b = append(b, hexOf(s))
		}
	}
	// Padding so the buckets are not all empty but one.
	for i := 0; i < 500; i++ {
		a = append(a, hexOf(fmt.Sprintf("padding-%d", i)))
	}
	virusShareFile(t, filepath.Join(src, "VirusShare_00000.md5.txt"), a)
	virusShareFile(t, filepath.Join(src, "VirusShare_00499.md5"), b)

	out := filepath.Join(t.TempDir(), "hashdb.bin")
	if _, err := Build(src, out, nil); err != nil {
		t.Fatalf("build: %v", err)
	}
	db, err := Open(out)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db, out
}

func TestBuildAndLookup(t *testing.T) {
	known := []string{"sample-one", "sample-two", "sample-three", "sample-four"}
	db, _ := buildFixture(t, known)

	if got, want := db.Count(), 504; got != want {
		t.Fatalf("count = %d, want %d", got, want)
	}
	for _, s := range known {
		ok, err := db.Contains(sumOf(s))
		if err != nil {
			t.Fatalf("contains %q: %v", s, err)
		}
		if !ok {
			t.Errorf("%q was in the corpus but was not found", s)
		}
	}
	for _, s := range []string{"clean-file", "another-clean-file", "not in there at all"} {
		ok, err := db.Contains(sumOf(s))
		if err != nil {
			t.Fatalf("contains %q: %v", s, err)
		}
		if ok {
			t.Errorf("%q is not in the corpus but was reported as a match", s)
		}
	}
}

// A hash list that is all banner and no hashes must not produce an index that
// silently answers "no" forever; it must still round-trip correctly.
func TestEmptyCorpus(t *testing.T) {
	src := t.TempDir()
	virusShareFile(t, filepath.Join(src, "VirusShare_00000.md5"), nil)
	out := filepath.Join(t.TempDir(), "hashdb.bin")
	st, err := Build(src, out, nil)
	if err != nil {
		t.Fatal(err)
	}
	if st.Hashes != 0 {
		t.Fatalf("hashes = %d, want 0", st.Hashes)
	}
	db, err := Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if ok, err := db.Contains(sumOf("anything")); err != nil || ok {
		t.Fatalf("empty index matched: %v %v", ok, err)
	}
}

func TestDuplicatesAreCollapsed(t *testing.T) {
	src := t.TempDir()
	h := hexOf("repeated")
	virusShareFile(t, filepath.Join(src, "VirusShare_00000.md5"), []string{h, h, h})
	out := filepath.Join(t.TempDir(), "hashdb.bin")
	st, err := Build(src, out, nil)
	if err != nil {
		t.Fatal(err)
	}
	if st.Hashes != 1 || st.Duplicates != 2 {
		t.Fatalf("hashes=%d duplicates=%d, want 1 and 2", st.Hashes, st.Duplicates)
	}
}

// Upper-case hashes and CRLF line endings both appear in the wild.
func TestToleratesCaseAndCRLF(t *testing.T) {
	src := t.TempDir()
	h := hexOf("mixed-case")
	body := "# banner\r\n" + hexOf("plain") + "\r\n" +
		upper(h) + "\r\n" + "   \r\n" + "not-a-hash\r\n"
	if err := os.WriteFile(filepath.Join(src, "VirusShare_00001.md5"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "hashdb.bin")
	if _, err := Build(src, out, nil); err != nil {
		t.Fatal(err)
	}
	db, err := Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if db.Count() != 2 {
		t.Fatalf("count = %d, want 2", db.Count())
	}
	for _, s := range []string{"plain", "mixed-case"} {
		if ok, _ := db.Contains(sumOf(s)); !ok {
			t.Errorf("%q not found", s)
		}
	}
}

func upper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'f' {
			b[i] -= 32
		}
	}
	return string(b)
}

func TestOpenMissingIsNotBuilt(t *testing.T) {
	_, err := Open(filepath.Join(t.TempDir(), "absent.bin"))
	if !errors.Is(err, ErrNotBuilt) {
		t.Fatalf("err = %v, want ErrNotBuilt", err)
	}
}

func TestOpenRejectsForeignFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hashdb.bin")
	if err := os.WriteFile(p, make([]byte, entriesAt+64), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p); err == nil {
		t.Fatal("a file with no magic was accepted")
	}
}

// A half-copied index would otherwise answer "no" for every hash past the cut,
// which is the worst possible failure for a check like this.
func TestOpenRejectsTruncatedIndex(t *testing.T) {
	_, path := buildFixture(t, []string{"a", "b"})
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, st.Size()-6); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("a truncated index was accepted")
	}
}

func TestBuildRejectsEmptyDirectory(t *testing.T) {
	if _, err := Build(t.TempDir(), filepath.Join(t.TempDir(), "x.bin"), nil); err == nil {
		t.Fatal("a directory with no hash lists was accepted")
	}
}

func TestSourceFilesFindsBothExtensions(t *testing.T) {
	src := t.TempDir()
	for _, n := range []string{"VirusShare_00000.md5.txt", "VirusShare_00044.md5", "README.md", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(src, n), []byte("#\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := SourceFiles(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("found %v, want the two VirusShare files only", got)
	}
}
