//go:build !windows && !darwin

package browse

import (
	"errors"
	"os/exec"
)

// openers are tried in order; a headless machine has none of them, which is
// not an error worth interrupting a scan for.
var openers = []string{"xdg-open", "gio", "gnome-open", "kde-open"}

func open(path string) error {
	for _, name := range openers {
		if _, err := exec.LookPath(name); err != nil {
			continue
		}
		if err := exec.Command(name, path).Start(); err == nil {
			return nil
		}
	}
	return errors.New("no desktop file handler is available")
}
