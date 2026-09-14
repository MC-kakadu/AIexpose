//go:build darwin

package netstat

import (
	"strconv"
	"strings"

	"github.com/MC-kakadu/AIexpose/internal/model"
)

// listeners shells out to lsof, which ships with macOS. Sockets owned by other
// users need root; without it we still see everything the current user runs.
func listeners() ([]model.Listener, error) {
	out, err := run("lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpcn")
	if err != nil || strings.TrimSpace(out) == "" {
		return fallbackNetstat()
	}
	var (
		res     []model.Listener
		curPID  int
		curName string
	)
	for _, line := range strings.Split(out, "\n") {
		if len(line) < 2 {
			continue
		}
		tag, val := line[0], line[1:]
		switch tag {
		case 'p':
			curPID, _ = strconv.Atoi(val)
			curName = ""
		case 'c':
			curName = val
		case 'n':
			addr, port, v6, ok := splitHostPort(val)
			if !ok {
				continue
			}
			res = append(res, model.Listener{
				Addr: addr, Port: port, PID: curPID, Process: curName, IPv6: v6,
			})
		}
	}
	if len(res) == 0 {
		return fallbackNetstat()
	}
	return res, nil
}

// fallbackNetstat parses `netstat -an -p tcp` when lsof is unavailable.
// It yields addresses without process attribution.
func fallbackNetstat() ([]model.Listener, error) {
	out, err := run("netstat", "-an", "-p", "tcp")
	if err != nil {
		return nil, err
	}
	var res []model.Listener
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "LISTEN") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		addr, port, v6, ok := splitHostPort(darwinAddr(f[3]))
		if !ok {
			continue
		}
		res = append(res, model.Listener{Addr: addr, Port: port, IPv6: v6})
	}
	return res, nil
}

// darwinAddr converts BSD netstat's "127.0.0.1.11434" into "127.0.0.1:11434".
func darwinAddr(s string) string {
	i := strings.LastIndex(s, ".")
	if i < 0 {
		return s
	}
	return s[:i] + ":" + s[i+1:]
}

// splitHostPort handles "127.0.0.1:11434", "*:8080" and "[::1]:8080".
func splitHostPort(s string) (string, int, bool, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, false, false
	}
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", 0, false, false
	}
	host, portStr := s[:i], s[i+1:]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, false, false
	}
	v6 := strings.HasPrefix(host, "[") || strings.Count(host, ":") > 0
	host = strings.Trim(host, "[]")
	if host == "*" {
		if v6 {
			host = "::"
		} else {
			host = "0.0.0.0"
		}
	}
	return host, port, v6, true
}
