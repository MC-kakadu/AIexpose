//go:build linux

package netstat

import (
	"bufio"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/MC-kakadu/AIexpose/internal/model"
)

const tcpListen = "0A"

func listeners() ([]model.Listener, error) {
	inodeToPID := buildInodeMap()

	var out []model.Listener
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Scan() // header
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 10 || fields[3] != tcpListen {
				continue
			}
			addr, port, v6, ok := parseHexAddr(fields[1])
			if !ok {
				continue
			}
			l := model.Listener{Addr: addr, Port: port, IPv6: v6}
			if pid, found := inodeToPID[fields[9]]; found {
				l.PID = pid
				l.Process = processName(pid)
			}
			out = append(out, l)
		}
		f.Close()
	}
	return out, nil
}

// parseHexAddr decodes the little-endian hex address /proc uses.
func parseHexAddr(s string) (string, int, bool, bool) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0, false, false
	}
	port64, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return "", 0, false, false
	}
	raw, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", 0, false, false
	}
	switch len(raw) {
	case 4:
		ip := net.IPv4(raw[3], raw[2], raw[1], raw[0])
		return ip.String(), int(port64), false, true
	case 16:
		// Four 32-bit little-endian words.
		b := make([]byte, 16)
		for w := 0; w < 4; w++ {
			for i := 0; i < 4; i++ {
				b[w*4+i] = raw[w*4+3-i]
			}
		}
		return net.IP(b).String(), int(port64), true, true
	}
	return "", 0, false, false
}

// buildInodeMap links socket inodes to owning PIDs by walking /proc/*/fd.
// Sockets owned by other users are silently skipped.
func buildInodeMap() map[string]int {
	m := map[string]int{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return m
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(filepath.Join("/proc", e.Name(), "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join("/proc", e.Name(), "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			m[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = pid
		}
	}
	return m
}

func processName(pid int) string {
	dir := filepath.Join("/proc", strconv.Itoa(pid))
	if b, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil && len(b) > 0 {
		cmd := strings.TrimSpace(strings.ReplaceAll(strings.TrimRight(string(b), "\x00"), "\x00", " "))
		if cmd != "" {
			if len(cmd) > 160 {
				cmd = cmd[:160] + "..."
			}
			return cmd
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil {
		return strings.TrimSpace(string(b))
	}
	return ""
}
