package browse

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/MC-kakadu/AIexpose/internal/subproc"
)

// Safe mode prints "no helper programs were started". A browser is a helper
// program. This package is the one place the rest of the program deliberately
// starts something, which is exactly why the safe-mode switch was missed here
// after it was added everywhere else.
func TestSafeModeOpensNothing(t *testing.T) {
	subproc.Allowed = false
	t.Cleanup(func() { subproc.Allowed = true })

	if Available() {
		t.Error("Available() is true in safe mode")
	}

	dir := t.TempDir()
	page := filepath.Join(dir, "report.html")
	if err := os.WriteFile(page, []byte("<p>hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Open(page); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("Open in safe mode returned %v, want ErrNotAllowed", err)
	}
}

// A server reached over SSH has no desktop. xdg-open there can hand the file
// to a terminal browser, which seizes the window the person is reading their
// scan in -- worse than printing a path.
func TestNoGraphicalSessionOpensNothing(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		t.Skip("these platforms always have a shell that can open a file")
	}
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")

	if hasDisplay() {
		t.Fatal("hasDisplay() is true with neither DISPLAY nor WAYLAND_DISPLAY set")
	}
	if Available() {
		t.Error("Available() is true with no graphical session")
	}

	dir := t.TempDir()
	page := filepath.Join(dir, "report.html")
	if err := os.WriteFile(page, []byte("<p>hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Open(page); !errors.Is(err, ErrNoDisplay) {
		t.Errorf("Open with no display returned %v, want ErrNoDisplay", err)
	}
}

// Either display variable is enough: Wayland sessions often set only the second.
func TestEitherDisplayVariableCounts(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		t.Skip("not applicable")
	}
	for _, v := range []string{"DISPLAY", "WAYLAND_DISPLAY"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("DISPLAY", "")
			t.Setenv("WAYLAND_DISPLAY", "")
			t.Setenv(v, ":0")
			if !hasDisplay() {
				t.Errorf("hasDisplay() is false with %s set", v)
			}
		})
	}
}

// And a file that is not there is reported before anything is launched.
func TestMissingFileIsNotHandedToTheShell(t *testing.T) {
	if err := Open(filepath.Join(t.TempDir(), "absent.html")); err == nil {
		t.Error("a missing file was passed to the opener")
	}
}
