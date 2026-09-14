//go:build linux

package netstat

import "testing"

func TestParseHexAddr(t *testing.T) {
	cases := []struct {
		in       string
		wantIP   string
		wantPort int
		wantV6   bool
	}{
		// 0100007F is 127.0.0.1 little-endian; 2CAE is 11434.
		{"0100007F:2CAA", "127.0.0.1", 11434, false},
		{"00000000:1F90", "0.0.0.0", 8080, false},
		{"00000000000000000000000000000000:1FF6", "::", 8182, true},
		{"00000000000000000000000001000000:2000", "::1", 8192, true},
	}
	for _, c := range cases {
		ip, port, v6, ok := parseHexAddr(c.in)
		if !ok {
			t.Fatalf("parseHexAddr(%q) failed", c.in)
		}
		if ip != c.wantIP || port != c.wantPort || v6 != c.wantV6 {
			t.Errorf("parseHexAddr(%q) = %q,%d,%v; want %q,%d,%v",
				c.in, ip, port, v6, c.wantIP, c.wantPort, c.wantV6)
		}
	}
	if _, _, _, ok := parseHexAddr("garbage"); ok {
		t.Error("parseHexAddr accepted malformed input")
	}
}
