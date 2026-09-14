//go:build darwin

package procinfo

import "strconv"
import "strings"

func fullCommand(pid int) string {
	return strings.TrimSpace(runCmd("ps", "-o", "command=", "-p", strconv.Itoa(pid)))
}
