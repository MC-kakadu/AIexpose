// Package model defines the core data types shared by every check.
package model

import (
	"sort"
	"strings"
	"time"
)

// Severity ranks a finding.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Critical:
		return "CRITICAL"
	case High:
		return "HIGH"
	case Medium:
		return "MEDIUM"
	case Low:
		return "LOW"
	default:
		return "INFO"
	}
}

// Penalty is how many points a finding of this severity removes from the score.
func (s Severity) Penalty() int {
	switch s {
	case Critical:
		return 35
	case High:
		return 20
	case Medium:
		return 10
	case Low:
		return 4
	default:
		return 0
	}
}

// Listener is one listening TCP socket discovered on this machine.
type Listener struct {
	Addr    string `json:"addr"` // bind address as reported by the OS
	Port    int    `json:"port"`
	PID     int    `json:"pid"`
	Process string `json:"process"` // best-effort process name
	IPv6    bool   `json:"ipv6"`
}

// Exposure classifies a bind address.
type Exposure int

const (
	Loopback  Exposure = iota // 127.0.0.0/8, ::1 - safe
	LANBound                  // a specific non-loopback interface address
	AllIfaces                 // 0.0.0.0 or :: - reachable from every interface
)

func (e Exposure) String() string {
	switch e {
	case AllIfaces:
		return "all-interfaces"
	case LANBound:
		return "lan-bound"
	default:
		return "loopback"
	}
}

// Service is a recognised AI service bound to a port.
type Service struct {
	Name      string   `json:"name"` // e.g. "Ollama"
	Kind      string   `json:"kind"` // "llm-server", "ui", "vector-db", "notebook"
	Listener  Listener `json:"listener"`
	Exposure  Exposure `json:"-"`
	ExposureS string   `json:"exposure"`
	Confirmed bool     `json:"confirmed"` // HTTP fingerprint matched
	NoAuth    bool     `json:"no_auth"`   // API answered without credentials
	Evidence  string   `json:"evidence,omitempty"`
}

// Finding is a single reported issue.
type Finding struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Severity Severity `json:"-"`
	SevLabel string   `json:"severity"`
	Detail   string   `json:"detail"`
	Fix      string   `json:"fix,omitempty"`
	Ref      string   `json:"ref,omitempty"`

	// Command is a single line the reader can run to resolve the finding. The
	// HTML report offers it as one click to copy; the terminal prints it.
	Command string `json:"command,omitempty"`

	// Evidence is the full list of what the finding is about: every file,
	// every mapping, every matched line. It is never truncated here. The
	// terminal shows the first few, the HTML report folds all of them behind
	// a disclosure, and the JSON output carries the lot.
	Evidence []string `json:"evidence,omitempty"`

	// Advisory marks a finding about the scan rather than about the machine:
	// a check that could not run, a rule set that is missing. It is shown and
	// counted, but it does not move the exposure grade, because the grade
	// answers "how exposed is this machine" and a gap in our coverage is not
	// an answer to that. It does mark the report incomplete.
	Advisory bool `json:"advisory,omitempty"`

	// NotRun marks an Info finding that records a check which did not happen.
	// It is not Advisory -- an opt-in extra left switched off does not make a
	// report incomplete -- but it must never be filed under "checks that
	// passed", because nothing passed.
	NotRun bool `json:"not_run,omitempty"`

	// Artifacts names the inventory components this finding is about, by their
	// stable IDs. Several MCP servers share one config file, so a path is not
	// an identity; this is.
	Artifacts []string `json:"artifacts,omitempty"`

	// Controls names the published risks and techniques this finding is
	// evidence for. It is what lets a reader take one line of this report to a
	// security questionnaire, a risk register or an auditor and have it mean
	// something outside this tool.
	Controls []Control `json:"controls,omitempty"`
}

// Control is one entry in a published security framework.
type Control struct {
	Framework string `json:"framework"`
	ID        string `json:"id"`
	Title     string `json:"title"`
	URL       string `json:"url,omitempty"`
}

// Coverage scope values. The distinction between them is the point of the
// whole section: a reader needs to know which risks this scan actually looked
// at before a clean result means anything.
const (
	// ScopeChecked means the scan examines this risk directly and a clean
	// result is a real result.
	ScopeChecked = "checked"
	// ScopePartial means the scan sees part of this risk and is blind to the
	// rest. Note says which part.
	ScopePartial = "partial"
	// ScopeNotChecked means a local scan cannot speak to this risk at all.
	ScopeNotChecked = "not-checked"
)

// ControlCoverage is what this scan can and cannot say about one control.
//
// A scanner that lists only what it found invites the reader to assume it
// looked everywhere. Publishing the gaps beside the findings is the difference
// between a report and a claim.
type ControlCoverage struct {
	Control  Control  `json:"control"`
	Scope    string   `json:"scope"`
	Note     string   `json:"note"`
	Findings []string `json:"findings,omitempty"`
	// Severity is the worst severity among Findings, so the summary can be
	// read at a glance.
	Severity Severity `json:"-"`
	SevLabel string   `json:"severity,omitempty"`
}

// Component is one installed piece of the AI stack, reduced to what a reader
// needs to recognise it. The report lists these because "6 components match
// the baseline" is a claim, and the list is the evidence for it.
type Component struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Source  string `json:"source,omitempty"`
	Digest  string `json:"digest,omitempty"`
	Path    string `json:"path,omitempty"`
	// Flag marks a component this report has a RISK finding about, so the
	// table and the findings cannot be read as describing different machines.
	Flag string `json:"flag,omitempty"`

	// State is a review item rather than a risk: a component that is new since
	// the baseline is waiting to be vouched for, not suspected of anything.
	// Rendering the two the same way tells someone their own freshly pulled
	// model is a threat.
	State string `json:"state,omitempty"`

	// StateSev is the severity the report gave that review item, so the table
	// shows the same weight the finding does rather than an unlabelled chip.
	StateSev string `json:"state_severity,omitempty"`
}

// Attestation records what produced this report, so a reader can reproduce it
// and an auditor can tell which version of which rule set made each claim.
type Attestation struct {
	Tool        string `json:"tool"`
	Version     string `json:"version"`
	Profile     string `json:"profile"`
	SelfDigest  string `json:"self_digest,omitempty"`
	ExePath     string `json:"executable,omitempty"`
	RuleVersion string `json:"rule_version,omitempty"`
	RuleOrigin  string `json:"rule_origin,omitempty"`
	RuleCounts  string `json:"rule_counts,omitempty"`
	HashIndex   string `json:"hash_index,omitempty"`
	Components  int    `json:"components"`
}

// Report is the full scan result.
type Report struct {
	Tool     string    `json:"tool"`
	Version  string    `json:"version"`
	Started  time.Time `json:"started"`
	Duration string    `json:"duration"`
	Host     string    `json:"host"`
	OS       string    `json:"os"`
	Arch     string    `json:"arch"`
	Score    int       `json:"score"`
	Grade    string    `json:"grade"`
	// Incomplete is set when a check could not run, so a good grade is never
	// mistaken for full coverage.
	Incomplete bool      `json:"incomplete"`
	Services   []Service `json:"services"`
	Findings   []Finding `json:"findings"`
	Notes      []string  `json:"notes,omitempty"`

	// Coverage is the per-control map of what this scan examined. It is filled
	// after Finalize, from the findings themselves.
	Coverage []ControlCoverage `json:"coverage,omitempty"`

	// Components is the AI stack inventory this scan fingerprinted.
	Components []Component `json:"components,omitempty"`

	// Attest records what produced the report.
	Attest Attestation `json:"attestation"`
}

// Add appends a finding, filling the string label.
func (r *Report) Add(f Finding) {
	f.SevLabel = f.Severity.String()
	r.Findings = append(r.Findings, f)
}

// Note records a non-finding remark (e.g. a check that could not run).
func (r *Report) Note(s string) { r.Notes = append(r.Notes, s) }

// Finalize sorts findings by severity and computes the score.
func (r *Report) Finalize() {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		return r.Findings[i].Severity > r.Findings[j].Severity
	})
	score := 100
	for _, f := range r.Findings {
		if f.Advisory {
			r.Incomplete = true
			continue
		}
		score -= f.Severity.Penalty()
	}
	if score < 0 {
		score = 0
	}
	r.Score = score
	switch {
	case score >= 90:
		r.Grade = "A"
	case score >= 75:
		r.Grade = "B"
	case score >= 60:
		r.Grade = "C"
	case score >= 40:
		r.Grade = "D"
	default:
		r.Grade = "F"
	}
	for i := range r.Services {
		r.Services[i].ExposureS = r.Services[i].Exposure.String()
	}
}

// Counts returns how many findings sit at each severity.
func (r *Report) Counts() map[string]int {
	m := map[string]int{}
	for _, f := range r.Findings {
		m[f.Severity.String()]++
	}
	return m
}

// MaskSecret redacts all but a short prefix and suffix of a credential.
func MaskSecret(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 10 {
		return strings.Repeat("*", len(s))
	}
	return s[:6] + strings.Repeat("*", 8) + s[len(s)-3:]
}
