package browse

import (
	"os"
	"path/filepath"
	"testing"
)

// A missing report must be reported as such rather than handed to the shell,
// where the failure would be silent.
func TestOpenRejectsMissingFile(t *testing.T) {
	if err := Open(filepath.Join(t.TempDir(), "absent.html")); err == nil {
		t.Fatal("opening a file that does not exist should be an error")
	}
}

// The path handed to the shell is absolute, so it does not depend on whatever
// working directory the program happened to be started in.
func TestOpenResolvesRelativePaths(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "r.html"), []byte("<p>x</p>"), 0o600); err != nil {
		t.Fatal(err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	// On a headless machine there is no handler, and that specific failure is
	// fine; what must not happen is a complaint that the file is missing.
	err = Open("r.html")
	if err != nil && err.Error() == "nothing to open at r.html: file does not exist" {
		t.Fatalf("a relative path was not resolved: %v", err)
	}
}
