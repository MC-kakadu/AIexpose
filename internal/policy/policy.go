// Package policy is the rule set a repository enforces on the AI components it
// ships: which MCP servers, agent skills and workflow nodes are allowed in.
//
// This is the piece that makes the tool a gate rather than an opinion. A report
// is read once and forgotten; a gate has to be satisfied before code merges.
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Level is how seriously a rule is taken.
type Level string

const (
	Error  Level = "error"  // fails the build
	Warn   Level = "warn"   // reported, does not fail
	Ignore Level = "ignore" // not reported at all
)

// Rule names a class of violation.
type Rule string

const (
	// A component matched the signed known-bad list.
	KnownBad Rule = "known_bad"
	// A component's source contains credential theft or exfiltration.
	RiskIndicator Rule = "risk_indicator"
	// An MCP server runs a registry package without a pinned version, so what
	// executes tomorrow is whatever the registry serves then.
	UnpinnedPackage Rule = "unpinned_package"
	// A component is present that the committed lockfile does not list.
	Unlocked Rule = "unlocked_component"
	// A locked component's contents no longer match the lockfile.
	LockDrift Rule = "lock_drift"
)

// AllRules is every rule, in report order.
var AllRules = []Rule{KnownBad, RiskIndicator, UnpinnedPackage, LockDrift, Unlocked}

// Exemption suppresses one rule for one component, on the record.
type Exemption struct {
	Rule    Rule   `json:"rule"`
	Match   Match  `json:"match"`
	Reason  string `json:"reason"`
	Expires string `json:"expires,omitempty"` // YYYY-MM-DD
}

// Match identifies what an exemption applies to. An exemption with no fields
// set matches nothing: a blanket waiver should have to be spelled out.
type Match struct {
	Component string `json:"component,omitempty"` // component name
	Package   string `json:"package,omitempty"`   // registry package name
	Path      string `json:"path,omitempty"`      // repo-relative path prefix
}

// Policy is the whole rule set, loaded from .aiexpose.json.
type Policy struct {
	Version    int            `json:"version"`
	Rules      map[Rule]Level `json:"rules,omitempty"`
	Exemptions []Exemption    `json:"exemptions,omitempty"`
	Source     string         `json:"-"`
}

// FileName is the policy file a repository commits.
const FileName = ".aiexpose.json"

// Default is what applies when a repository has no policy file. It fails on the
// things that are unambiguously wrong and merely warns about the rest, so
// adding this to an existing repository does not immediately break its build.
func Default() Policy {
	return Policy{
		Version: 1,
		Rules: map[Rule]Level{
			KnownBad:        Error,
			RiskIndicator:   Error,
			UnpinnedPackage: Warn,
			LockDrift:       Error,
			Unlocked:        Warn,
		},
		Source: "built-in defaults",
	}
}

// Load reads a repository's policy, falling back to the defaults.
func Load(path string) (Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Default(), nil
		}
		return Default(), err
	}
	p := Default()
	var onDisk Policy
	if err := json.Unmarshal(b, &onDisk); err != nil {
		return Default(), fmt.Errorf("%s is not readable: %w", path, err)
	}
	if onDisk.Version != 0 && onDisk.Version != 1 {
		return Default(), fmt.Errorf("%s declares version %d, which this build does not understand", path, onDisk.Version)
	}
	for rule, level := range onDisk.Rules {
		if !validRule(rule) {
			return Default(), fmt.Errorf("%s names an unknown rule %q", path, rule)
		}
		if !validLevel(level) {
			return Default(), fmt.Errorf("%s sets rule %q to %q; use error, warn or ignore", path, rule, level)
		}
		p.Rules[rule] = level
	}
	p.Exemptions = onDisk.Exemptions
	p.Source = path
	return p, nil
}

// LevelFor returns how a rule is treated.
func (p Policy) LevelFor(r Rule) Level {
	if l, ok := p.Rules[r]; ok {
		return l
	}
	return Default().Rules[r]
}

// Subject is the component a rule is being applied to.
type Subject struct {
	Component string
	Package   string
	Path      string
}

// Exempt reports whether a rule is waived for a subject, and why.
//
// An expired exemption does not apply. That is the point of the field: a
// temporary waiver that silently becomes permanent is how these files rot.
func (p Policy) Exempt(r Rule, s Subject) (Exemption, bool) {
	for _, e := range p.Exemptions {
		if e.Rule != r || !e.Match.matches(s) {
			continue
		}
		if e.Expires != "" {
			until, err := time.Parse("2006-01-02", e.Expires)
			if err != nil || time.Now().After(until.Add(24*time.Hour)) {
				continue
			}
		}
		return e, true
	}
	return Exemption{}, false
}

func (m Match) matches(s Subject) bool {
	if m.Component == "" && m.Package == "" && m.Path == "" {
		return false // an empty match is not a wildcard
	}
	if m.Component != "" && !strings.EqualFold(m.Component, s.Component) {
		return false
	}
	if m.Package != "" && !strings.EqualFold(m.Package, s.Package) {
		return false
	}
	if m.Path != "" && !strings.HasPrefix(s.Path, m.Path) {
		return false
	}
	return true
}

// ExpiredExemptions lists waivers that have lapsed, so CI can say so instead of
// quietly enforcing a rule the team believes is waived.
func (p Policy) ExpiredExemptions() []Exemption {
	var out []Exemption
	for _, e := range p.Exemptions {
		if e.Expires == "" {
			continue
		}
		until, err := time.Parse("2006-01-02", e.Expires)
		if err != nil || time.Now().After(until.Add(24*time.Hour)) {
			out = append(out, e)
		}
	}
	return out
}

func validRule(r Rule) bool {
	for _, known := range AllRules {
		if r == known {
			return true
		}
	}
	return false
}

func validLevel(l Level) bool {
	return l == Error || l == Warn || l == Ignore
}
