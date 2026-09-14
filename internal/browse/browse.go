// Package browse opens a local file in whatever the user has set as its
// default handler.
//
// This is the one place aiexpose starts anything, and it does so only after a
// scan, on a report the person is standing there waiting for. On Windows it
// calls ShellExecuteW, the same entry point Explorer uses, rather than running
// `cmd /c start` or PowerShell: spawning a shell from an unsigned binary is a
// behavioural detection trigger, and this tool spent several versions removing
// exactly that.
package browse

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/MC-kakadu/AIexpose/internal/subproc"
)

// ErrNotAllowed is returned in safe mode. The report says in safe mode that no
// helper programs were started, and a browser is a helper program: launching
// one would make that sentence false. This is the same hole that was fixed in
// the firewall check, in the one place the rest of the program calls out as
// "the only thing aiexpose starts" -- which is exactly why it was missed.
var ErrNotAllowed = errors.New("safe mode starts no other programs")

// ErrNoDisplay is returned when there is no graphical session to open into.
// On a server reached over SSH, xdg-open with no DISPLAY can hand the job to a
// terminal browser, which takes over the window the person is reading. Naming
// the file is better than hijacking their terminal.
var ErrNoDisplay = errors.New("no graphical session to open a browser in")

// Available reports whether Open has any chance of working, so the caller can
// print a path instead of an error nobody needed to see.
func Available() bool { return subproc.Allowed && hasDisplay() }

// Open shows a file in its default application. It never blocks: the browser
// is launched and the scan carries on.
func Open(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if _, err := os.Stat(abs); err != nil {
		return fmt.Errorf("nothing to open at %s: %w", abs, err)
	}
	if !subproc.Allowed {
		return ErrNotAllowed
	}
	if !hasDisplay() {
		return ErrNoDisplay
	}
	return open(abs)
}
