//go:build linux

package checks

import (
	"fmt"
	"strings"
)

func firewallState() FirewallState {
	if out, ok := cmdOut("ufw", "status"); ok && strings.TrimSpace(out) != "" {
		l := strings.ToLower(out)
		if strings.Contains(l, "status: active") {
			return FirewallState{Known: true, Enabled: true, Detail: "ufw reports status: active."}
		}
		if strings.Contains(l, "status: inactive") {
			return FirewallState{Known: true, Enabled: false, Detail: "ufw reports status: inactive."}
		}
	}
	if out, ok := cmdOut("firewall-cmd", "--state"); ok {
		l := strings.TrimSpace(strings.ToLower(out))
		if l == "running" {
			return FirewallState{Known: true, Enabled: true, Detail: "firewalld is running."}
		}
		if l != "" {
			return FirewallState{Known: true, Enabled: false, Detail: "firewalld reports: " + l + "."}
		}
	}
	if out, ok := cmdOut("nft", "list", "ruleset"); ok && strings.TrimSpace(out) != "" {
		if rules, drops, sawInput := nftInput(out); sawInput {
			switch {
			case drops:
				return FirewallState{Known: true, Enabled: true, Detail: "nftables has an input chain with a drop policy."}
			case rules > 0:
				return FirewallState{Known: true, Enabled: true,
					Detail: fmt.Sprintf("nftables has an input chain with %d rule(s).", rules)}
			default:
				return FirewallState{Known: true, Enabled: false,
					Detail: "nftables has an input chain, but it is empty and its policy is accept."}
			}
		}
	}
	if out, ok := cmdOut("iptables", "-S", "INPUT"); ok && strings.TrimSpace(out) != "" {
		lines := 0
		for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
			if strings.HasPrefix(ln, "-A ") {
				lines++
			}
		}
		if strings.Contains(out, "-P INPUT DROP") || lines > 0 {
			return FirewallState{Known: true, Enabled: true, Detail: "iptables INPUT chain has a restrictive policy or rules."}
		}
		return FirewallState{Known: true, Enabled: false, Detail: "iptables INPUT chain is empty with an ACCEPT policy."}
	}
	return FirewallState{Detail: "no ufw, firewalld, nftables or iptables output was readable (this usually needs root)"}
}

func firewallFix() string {
	return "Enable a host firewall, for example: sudo ufw default deny incoming && sudo ufw enable. Then allow only the ports you deliberately serve."
}

// nftInput counts the real rules in every input-hooked chain of an nft ruleset.
//
// The declaration of a chain is not a firewall. An empty "chain INPUT { type
// filter hook input priority filter; policy accept; }" appears the moment any
// tool touches the ip filter table, and matching on the words "hook input"
// alone reported that machine as protected when nothing was being filtered.
// That is the worst kind of wrong answer this tool can give: a pass on a
// machine that has no firewall at all.
func nftInput(out string) (rules int, drop, saw bool) {
	depth := 0
	inChain := false
	chainHooksInput := false
	var pending int
	var pendingDrop bool
	flush := func() {
		if chainHooksInput {
			saw = true
			rules += pending
			drop = drop || pendingDrop
		}
		chainHooksInput, pending, pendingDrop = false, 0, false
	}
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		opens := strings.Count(line, "{")
		closes := strings.Count(line, "}")
		if strings.HasPrefix(line, "chain ") && opens > 0 {
			flush()
			inChain = true
			depth += opens - closes
			continue
		}
		if inChain {
			switch {
			case line == "}":
				depth += opens - closes
				if depth <= 1 {
					flush()
					inChain = false
				}
				continue
			case strings.HasPrefix(line, "type ") && strings.Contains(line, "hook input"):
				chainHooksInput = true
				lower := strings.ToLower(line)
				if strings.Contains(lower, "policy drop") || strings.Contains(lower, "policy reject") {
					pendingDrop = true
				}
			case strings.HasPrefix(line, "policy "):
				lower := strings.ToLower(line)
				if strings.Contains(lower, "drop") || strings.Contains(lower, "reject") {
					pendingDrop = true
				}
			default:
				// Anything else inside the chain body is an actual rule.
				pending++
			}
		}
		depth += opens - closes
	}
	flush()
	return rules, drop, saw
}
