package checks

import (
	"testing"

	"github.com/MC-kakadu/AIexpose/internal/subproc"
)

// Safe mode prints "no helper programs were started". The firewall check used
// to run ufw, firewall-cmd, nft and iptables regardless, which made that
// sentence false on every safe-mode scan.
func TestSafeModeStartsNoHelperProgram(t *testing.T) {
	subproc.Allowed = false
	t.Cleanup(func() { subproc.Allowed = true })

	// A command that exists everywhere and would obviously succeed.
	if out, ok := cmdOut("echo", "started"); ok || out != "" {
		t.Fatalf("cmdOut ran a helper program in safe mode: out=%q ok=%v", out, ok)
	}
}

// And the report must then say the state is unknown rather than guessing.
func TestSafeModeReportsFirewallStateAsUnknown(t *testing.T) {
	subproc.Allowed = false
	t.Cleanup(func() { subproc.Allowed = true })

	if st := firewallState(); st.Known {
		t.Fatalf("firewall state claimed to be known in safe mode: %+v", st)
	}
}
