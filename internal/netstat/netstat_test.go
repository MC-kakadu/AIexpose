package netstat

import (
	"testing"

	"github.com/MC-kakadu/AIexpose/internal/model"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		addr string
		want model.Exposure
	}{
		{"127.0.0.1", model.Loopback},
		{"127.0.1.1", model.Loopback},
		{"::1", model.Loopback},
		{"[::1]", model.Loopback},
		{"0.0.0.0", model.AllIfaces},
		{"::", model.AllIfaces},
		{"[::]", model.AllIfaces},
		{"*", model.AllIfaces},
		{"", model.AllIfaces},
		{"192.168.1.42", model.LANBound},
		{"10.0.0.7", model.LANBound},
		{"fe80::1", model.LANBound},
	}
	for _, c := range cases {
		if got := Classify(c.addr); got != c.want {
			t.Errorf("Classify(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}
