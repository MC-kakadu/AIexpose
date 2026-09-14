// Package procinfo resolves a PID to its full command line, which is where
// dangerous launch flags such as --listen or --share show up.
package procinfo

import (
	"os/exec"
	"time"

	"github.com/MC-kakadu/AIexpose/internal/subproc"
)

// FullCommand returns the complete command line for pid, or "" if unavailable.
func FullCommand(pid int) string { return fullCommand(pid) }

func runCmd(name string, args ...string) string {
	if !subproc.Allowed {
		return ""
	}
	cmd := exec.Command(name, args...)
	done := make(chan struct{})
	var out []byte
	go func() { out, _ = cmd.Output(); close(done) }()
	select {
	case <-done:
		return string(out)
	case <-time.After(6 * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return ""
	}
}
