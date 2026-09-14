package checks

import (
	"os"
	"path/filepath"
	"testing"
)

// Someone who cloned the repository and ran "go build" has no
// aiexpose-rules.json: that name belongs to a release asset. Telling them to
// install it names a file that does not exist, while the one that does sits in
// the tree they just built from.
func TestRulesAdviceNamesTheFileASourceBuildActuallyHas(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, filepath.FromSlash(repoRulesPath))
	if err := os.MkdirAll(filepath.Dir(repo), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{repo, repo + ".sig"} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)

	got := rulesFileToSuggest()
	if got == releaseRulesName {
		t.Fatalf("advice names %q, which does not exist in a source checkout", got)
	}
	if _, err := os.Stat(got); err != nil {
		t.Fatalf("advice names %q, which cannot be opened: %v", got, err)
	}
}

// A release folder has the other name, and that is still what most people have.
func TestRulesAdviceNamesTheReleaseFileBesideABinary(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{releaseRulesName, releaseRulesName + ".sig"} {
		if err := os.WriteFile(filepath.Join(dir, p), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)

	if got := rulesFileToSuggest(); got != releaseRulesName {
		t.Errorf("advice = %q, want %q", got, releaseRulesName)
	}
}

// With nothing on disk the release name is the right instruction, because that
// is what the reader will have after downloading one.
func TestRulesAdviceFallsBackToTheReleaseName(t *testing.T) {
	t.Chdir(t.TempDir())
	if got := rulesFileToSuggest(); got != releaseRulesName {
		t.Errorf("advice = %q, want %q", got, releaseRulesName)
	}
}

// A rule file with no signature beside it is not installable, so naming it
// would send the reader into a verification failure.
func TestUnsignedRuleFileIsNotSuggested(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, releaseRulesName), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	// Falls back to the bare name rather than pointing at the unsigned copy;
	// either way it must not claim an unsigned file is ready to install.
	if got := rulesFileToSuggest(); got != releaseRulesName {
		t.Errorf("advice = %q", got)
	}
}
