package main

import "testing"

// A browser window thrown at a scheduled task or a CI job is a bug. It opens
// for the double-click case it exists for, and when explicitly asked.
func TestShouldOpenReport(t *testing.T) {
	cases := []struct {
		name           string
		force, disable bool
		want           bool
	}{
		{"asked for it", true, false, true},
		{"asked and refused", true, true, false},
		{"refused", false, true, false},
		// Under `go test` this process does not own a console, which stands in
		// for every non-interactive run: a shell, cron, CI.
		{"neither, not a double-click", false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := shouldOpenReport(c.force, c.disable); got != c.want {
				t.Errorf("shouldOpenReport(force=%v, disable=%v) = %v, want %v",
					c.force, c.disable, got, c.want)
			}
		})
	}
}
