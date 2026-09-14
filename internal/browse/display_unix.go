//go:build !windows && !darwin

package browse

import "os"

// hasDisplay reports whether this session has a graphical desktop to open into.
//
// Without it, xdg-open may hand the file to a terminal browser, which seizes
// the window the person is reading their scan in. Over SSH with no X11
// forwarding that is the normal case, and a printed path is the right answer.
func hasDisplay() bool {
	return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
}
