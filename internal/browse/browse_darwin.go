//go:build darwin

package browse

import "os/exec"

func open(path string) error {
	return exec.Command("open", path).Start()
}
