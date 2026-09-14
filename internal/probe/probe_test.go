package probe

import (
	"testing"

	"github.com/MC-kakadu/AIexpose/internal/model"
)

// A desktop app's helper process takes a fresh ephemeral port on every launch.
// Matching it on process name alone reported the same product twice and asked
// the user to act on a port that will not exist tomorrow.
func TestIsNoise(t *testing.T) {
	cases := []struct {
		name      string
		port      int
		confirmed bool
		want      bool
	}{
		{"unconfirmed guess on an ephemeral port", 52739, false, true},
		{"confirmed service on an ephemeral port", 52739, true, false},
		{"unconfirmed guess on a service port", 11434, false, false},
		{"confirmed service on a service port", 11434, true, false},
		{"just below the ephemeral range", 49151, false, false},
		{"first ephemeral port", 49152, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := model.Service{
				Confirmed: c.confirmed,
				Listener:  model.Listener{Port: c.port},
			}
			if got := isNoise(s); got != c.want {
				t.Errorf("isNoise(port %d, confirmed %v) = %v, want %v",
					c.port, c.confirmed, got, c.want)
			}
		})
	}
}
