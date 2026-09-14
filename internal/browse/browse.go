// Package browse opens a local file in whatever the user has set as its
// default handler.
//
// This is the one place aiexpose starts anything, and it does so only after a
// scan the user launched by double-clicking. On Windows it calls ShellExecuteW,
// the same entry point Explorer uses, rather than running `cmd /c start` or
// PowerShell: spawning a shell from an unsigned binary is a behavioural
// detection trigger, and this tool spent several versions removing exactly that.
package browse

import (
	"fmt"
	"os"
	"path/filepath"
)

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
	return open(abs)
}
