package checks

import (
	"os/exec"
	"time"

	"github.com/MC-kakadu/AIexpose/internal/advice"
	"github.com/MC-kakadu/AIexpose/internal/model"
	"github.com/MC-kakadu/AIexpose/internal/subproc"
)

// FirewallState is the host firewall's status as best we can determine it.
type FirewallState struct {
	Known   bool
	Enabled bool
	Detail  string
}

// Firewall reports a disabled or unknown host firewall, weighted by whether
// anything is actually exposed.
func Firewall(r *model.Report, services []model.Service) {
	st := firewallState()
	exposed := false
	for _, s := range services {
		if s.Exposure != model.Loopback {
			exposed = true
			break
		}
	}

	switch {
	case !st.Known:
		if !subproc.Allowed {
			// Saying "usually needs root" here would blame the wrong thing:
			// safe mode is why nothing was read, and the user chose it.
			r.Note("Host firewall state was not read: safe mode starts no helper programs, and every way to " +
				"read it (ufw, firewalld, nftables, iptables) is one. Re-run without --safe-mode to include it.")
			break
		}
		r.Note("Host firewall state could not be determined: " + st.Detail)
	case st.Enabled:
		r.Add(model.Finding{
			ID: "FW-000", Title: "Host firewall is enabled", Severity: model.Info,
			Detail: st.Detail,
		})
	case exposed:
		r.Add(model.Finding{
			ID: "FW-001", Title: "Host firewall is off while AI services are exposed",
			Severity: model.High,
			Detail:   st.Detail + "\nWith no host firewall, a service bound to a wildcard address is reachable from every network this machine joins, including untrusted Wi-Fi.",
			Fix:      firewallFix(),
			Command:  advice.EnableFirewall(),
		})
	default:
		r.Add(model.Finding{
			ID: "FW-002", Title: "Host firewall is off", Severity: model.Low,
			Detail:  st.Detail + "\nNothing is currently exposed, but the firewall is your second line of defence if a service is later started with the wrong bind address.",
			Fix:     firewallFix(),
			Command: advice.EnableFirewall(),
		})
	}
}

// cmdOut runs a read-only query command. It returns nothing in safe mode:
// the firewall state is worth knowing, but not at the cost of making the
// report's "no helper programs were started" note false.
func cmdOut(name string, args ...string) (string, bool) {
	if !subproc.Allowed {
		return "", false
	}
	if _, err := exec.LookPath(name); err != nil {
		return "", false
	}
	cmd := exec.Command(name, args...)
	done := make(chan struct{})
	var out []byte
	go func() { out, _ = cmd.Output(); close(done) }()
	select {
	case <-done:
		return string(out), true
	case <-time.After(8 * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return "", false
	}
}
