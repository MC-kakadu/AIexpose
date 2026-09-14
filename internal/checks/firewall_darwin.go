//go:build darwin

package checks

import "strings"

func firewallState() FirewallState {
	out, ok := cmdOut("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")
	if !ok || strings.TrimSpace(out) == "" {
		return FirewallState{Detail: "socketfilterfw did not return a state"}
	}
	l := strings.ToLower(out)
	switch {
	case strings.Contains(l, "state = 1"), strings.Contains(l, "state = 2"):
		return FirewallState{Known: true, Enabled: true, Detail: "macOS application firewall is enabled."}
	case strings.Contains(l, "state = 0"):
		return FirewallState{Known: true, Enabled: false, Detail: "macOS application firewall is disabled."}
	}
	return FirewallState{Detail: "unrecognised socketfilterfw output"}
}

func firewallFix() string {
	return "Turn on the firewall in System Settings > Network > Firewall, and enable stealth mode. Note that the macOS application firewall does not filter by port, so binding services to 127.0.0.1 remains the primary control."
}
