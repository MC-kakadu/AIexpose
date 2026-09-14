//go:build !linux && !darwin && !windows

package checks

func firewallState() FirewallState {
	return FirewallState{Detail: "firewall detection is not implemented for this operating system"}
}

func firewallFix() string {
	return "Enable a host firewall that denies inbound connections by default."
}
