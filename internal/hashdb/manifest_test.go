package hashdb

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildTestIndex writes a small but real index and returns its path.
func buildTestIndex(t *testing.T, dir string) string {
	t.Helper()
	src := filepath.Join(dir, "lists")
	if err := os.MkdirAll(src, 0o700); err != nil {
		t.Fatal(err)
	}
	lines := []string{
		"d41d8cd98f00b204e9800998ecf8427e",
		"0123456789abcdef0123456789abcdef",
		"fedcba9876543210fedcba9876543210",
	}
	if err := os.WriteFile(filepath.Join(src, "VirusShare_00000.md5"),
		[]byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "aiexpose-hashdb.bin")
	if _, err := Build(src, out, nil); err != nil {
		t.Fatal(err)
	}
	return out
}

// okVerify stands in for a signature that checks out. The real one is
// feed.Verify; this package deliberately does not import it.
func okVerify(_, _ []byte) error { return nil }

func badVerify(_, _ []byte) error { return errors.New("signature does not verify") }

func signManifest(t *testing.T, indexPath string) {
	t.Helper()
	if _, err := WriteManifest(indexPath, ""); err != nil {
		t.Fatal(err)
	}
	// A detached signature file has to exist; its content is whatever the
	// verify function accepts.
	if err := os.WriteFile(ManifestPath(indexPath)+".sig", []byte("00\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestInstallVerifiedIndex(t *testing.T) {
	dir := t.TempDir()
	idx := buildTestIndex(t, dir)
	signManifest(t, idx)

	dest := filepath.Join(t.TempDir(), "hashdb.bin")
	m, err := Install(idx, dest, okVerify)
	if err != nil {
		t.Fatalf("Install on a good index: %v", err)
	}
	if m.Meta.Source == "" {
		t.Error("the installed manifest carries no provenance")
	}
	db, err := Open(dest)
	if err != nil {
		t.Fatalf("the installed index does not open: %v", err)
	}
	defer db.Close()
	if db.Count() != 3 {
		t.Errorf("installed index holds %d hashes, want 3", db.Count())
	}
	// The provenance has to land beside it, or every report built on this
	// index would describe it as an anonymous corpus.
	if _, err := os.Stat(metaPath(dest)); err != nil {
		t.Errorf("no meta.json beside the installed index: %v", err)
	}
}

// A bad signature is the case this whole path exists for: whoever controls the
// index controls which files get called malware, and which get passed over in
// silence.
func TestInstallRejectsBadSignature(t *testing.T) {
	dir := t.TempDir()
	idx := buildTestIndex(t, dir)
	signManifest(t, idx)

	dest := filepath.Join(t.TempDir(), "hashdb.bin")
	if _, err := Install(idx, dest, badVerify); err == nil {
		t.Fatal("an index with an unverifiable manifest was installed")
	}
	if _, err := os.Stat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Error("a rejected index was written to the destination anyway")
	}
}

// Refusing a nil verifier matters because the mistake is silent otherwise: the
// install would work, and nothing would ever have been checked.
func TestInstallRefusesMissingVerifier(t *testing.T) {
	dir := t.TempDir()
	idx := buildTestIndex(t, dir)
	signManifest(t, idx)

	if _, err := Install(idx, filepath.Join(t.TempDir(), "hashdb.bin"), nil); err == nil {
		t.Fatal("an index was installed with no signature check at all")
	}
}

func TestInstallRejectsTamperedIndex(t *testing.T) {
	dir := t.TempDir()
	idx := buildTestIndex(t, dir)
	signManifest(t, idx)

	// Flip one byte inside the entry table, leaving the length intact so only
	// the digest can catch it.
	b, err := os.ReadFile(idx)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 0xff
	if err := os.WriteFile(idx, b, 0o600); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(t.TempDir(), "hashdb.bin")
	_, err = Install(idx, dest, okVerify)
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("a tampered index gave %v, want ErrDigestMismatch", err)
	}
	if _, err := os.Stat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Error("a tampered index was installed anyway")
	}
}

func TestInstallRejectsTruncatedIndex(t *testing.T) {
	dir := t.TempDir()
	idx := buildTestIndex(t, dir)
	signManifest(t, idx)

	b, err := os.ReadFile(idx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(idx, b[:len(b)-entryBytes], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(idx, filepath.Join(t.TempDir(), "hashdb.bin"), okVerify); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("a truncated index gave %v, want ErrDigestMismatch", err)
	}
}

func TestInstallReportsMissingManifest(t *testing.T) {
	dir := t.TempDir()
	idx := buildTestIndex(t, dir)

	_, err := Install(idx, filepath.Join(t.TempDir(), "hashdb.bin"), okVerify)
	if !errors.Is(err, ErrManifestMissing) {
		t.Fatalf("an index with no manifest gave %v, want ErrManifestMissing", err)
	}

	// Manifest present, signature absent: the same ordinary mistake, and it
	// must not be reported as corruption.
	if _, err := WriteManifest(idx, ""); err != nil {
		t.Fatal(err)
	}
	_, err = Install(idx, filepath.Join(t.TempDir(), "hashdb.bin"), okVerify)
	if !errors.Is(err, ErrManifestMissing) {
		t.Fatalf("an index with no signature gave %v, want ErrManifestMissing", err)
	}
}

func TestInstallRejectsMismatchedPair(t *testing.T) {
	dir := t.TempDir()
	idx := buildTestIndex(t, dir)
	signManifest(t, idx)

	// Rename the index so it no longer matches the name the manifest vouches
	// for. Two indexes downloaded into one folder is exactly how this happens.
	other := filepath.Join(dir, "aiexpose-hashdb-old.bin")
	if err := os.Rename(idx, other); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(ManifestPath(idx), ManifestPath(other)); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(ManifestPath(idx)+".sig", ManifestPath(other)+".sig"); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(other, filepath.Join(t.TempDir(), "hashdb.bin"), okVerify); err == nil {
		t.Fatal("an index was accepted under a manifest that names a different file")
	}
}

func TestReadManifestRejectsUnknownFormat(t *testing.T) {
	dir := t.TempDir()
	idx := buildTestIndex(t, dir)
	signManifest(t, idx)

	mp := ManifestPath(idx)
	b, err := os.ReadFile(mp)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	m["format"] = "aiexpose-hashdb-manifest/99"
	b, _ = json.Marshal(m)
	if err := os.WriteFile(mp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(idx, okVerify); err == nil {
		t.Fatal("a manifest in an unknown format was accepted")
	}
}

// An index with no provenance must not be publishable: a report that cannot
// say what corpus it matched against is asserting an anonymous verdict.
func TestWriteManifestRefusesIndexWithoutProvenance(t *testing.T) {
	dir := t.TempDir()
	idx := buildTestIndex(t, dir)
	if err := os.Remove(metaPath(idx)); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteManifest(idx, ""); err == nil {
		t.Fatal("an index with no meta.json was published anyway")
	}
}
