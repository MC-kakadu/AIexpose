// Package netstat enumerates listening TCP sockets without any third-party
// dependency. Every OS backend degrades to a partial answer rather than
// failing the whole scan.
package netstat

import (
	"net"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/MC-kakadu/AIexpose/internal/model"
	"github.com/MC-kakadu/AIexpose/internal/subproc"
)

// AllowSubprocess controls whether a backend may fall back to running a helper
// program when its in-process path fails. Safe mode turns it off, so a scan can
// be run on a machine whose endpoint protection objects to an unsigned binary
// starting other processes. It is kept in one place, subproc, because the
// report claims in safe mode that nothing was started and that claim has to
// hold for every package, not only this one.
func AllowSubprocess() bool { return subproc.Allowed }

// Listeners returns every listening TCP socket the current user can observe,
// de-duplicated and sorted by port.
func Listeners() ([]model.Listener, error) {
	ls, err := listeners()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := make([]model.Listener, 0, len(ls))
	for _, l := range ls {
		if l.Port <= 0 {
			continue
		}
		key := l.Addr + "/" + itoa(l.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Addr < out[j].Addr
	})
	return out, nil
}

// Classify maps a bind address to an exposure class.
func Classify(addr string) model.Exposure {
	a := strings.TrimSpace(addr)
	a = strings.Trim(a, "[]")
	switch a {
	case "0.0.0.0", "*", "::", "[::]", "":
		return model.AllIfaces
	}
	ip := net.ParseIP(a)
	if ip == nil {
		return model.LANBound
	}
	if ip.IsLoopback() {
		return model.Loopback
	}
	if ip.IsUnspecified() {
		return model.AllIfaces
	}
	return model.LANBound
}

// run executes a helper command with a hard timeout and returns stdout.
func run(name string, args ...string) (string, error) {
	if !AllowSubprocess() {
		return "", errSubprocessDisabled
	}
	cmd := exec.Command(name, args...)
	done := make(chan struct{})
	var out []byte
	var err error
	go func() {
		out, err = cmd.Output()
		close(done)
	}()
	select {
	case <-done:
		return string(out), err
	case <-time.After(12 * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return "", errTimeout
	}
}

type subprocessDisabledErr struct{}

func (subprocessDisabledErr) Error() string {
	return "running helper programs is disabled (--safe-mode)"
}

var errSubprocessDisabled = subprocessDisabledErr{}

type timeoutErr struct{}

func (timeoutErr) Error() string { return "command timed out" }

var errTimeout = timeoutErr{}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		p--
		b[p] = '-'
	}
	return string(b[p:])
}
