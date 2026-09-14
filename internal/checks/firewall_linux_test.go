//go:build linux

package checks

import "testing"

// An empty input chain is not a firewall. This exact ruleset appears on any
// machine where some tool has touched the ip filter table once; the first
// version of this check read it as "protected" and told an unprotected
// machine it was fine.
const emptyChain = `table ip filter {
	chain INPUT {
		type filter hook input priority filter; policy accept;
	}
}`

const oneRule = `table ip filter {
	chain INPUT {
		type filter hook input priority filter; policy accept;
		tcp dport 9999 counter packets 0 bytes 0 drop
	}
}`

const dropPolicy = `table inet fw {
	chain input {
		type filter hook input priority 0; policy drop;
	}
	chain output {
		type filter hook output priority 0; policy accept;
	}
}`

const outputOnly = `table inet fw {
	chain output {
		type filter hook output priority 0; policy accept;
		ip daddr 10.0.0.1 accept
	}
}`

func TestNftInput(t *testing.T) {
	cases := []struct {
		name      string
		ruleset   string
		wantSaw   bool
		wantRules int
		wantDrop  bool
	}{
		{"empty input chain", emptyChain, true, 0, false},
		{"one rule", oneRule, true, 1, false},
		{"drop policy", dropPolicy, true, 0, true},
		{"no input hook at all", outputOnly, false, 0, false},
		{"empty ruleset", "", false, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rules, drop, saw := nftInput(c.ruleset)
			if saw != c.wantSaw {
				t.Errorf("saw input chain = %v, want %v", saw, c.wantSaw)
			}
			if rules != c.wantRules {
				t.Errorf("rules = %d, want %d", rules, c.wantRules)
			}
			if drop != c.wantDrop {
				t.Errorf("drop = %v, want %v", drop, c.wantDrop)
			}
		})
	}
}

// The empty chain must produce "not enabled", because that is the difference
// between FW-000 (a pass) and FW-001 (a high-severity finding).
func TestEmptyInputChainIsNotAFirewall(t *testing.T) {
	rules, drop, saw := nftInput(emptyChain)
	if saw && (rules > 0 || drop) {
		t.Fatal("an empty accept-policy input chain was counted as an enabled firewall")
	}
}
