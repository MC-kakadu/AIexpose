//go:build linux

package procinfo

import (
	"os"
	"strconv"
	"strings"
)

func fullCommand(pid int) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(strings.TrimRight(string(b), "\x00"), "\x00", " "))
}
