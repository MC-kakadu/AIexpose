// Package ci enforces a repository's policy on the AI components it ships.
package ci

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/MC-kakadu/AIexpose/internal/feed"
	"github.com/MC-kakadu/AIexpose/internal/policy"
	"github.com/MC-kakadu/AIexpose/internal/supply"
)

// Options configures one CI run.
type Options struct {
	Dir        string
	PolicyPath string
	LockPath   string
	WriteLock  bool
	FeedPath   string
	NoFeed     bool
}

// Violation is one policy breach, or one that was waived.
type Violation struct {
	Rule      policy.Rule       `json:"rule"`
	Level     policy.Level      `json:"level"`
	Title     string            `json:"title"`
	Detail    string            `json:"detail"`
	Path      string            `json:"path"`
	Line      int               `json:"line,omitempty"`
	Ref       string            `json:"reference,omitempty"`
	Component string            `json:"component"`
	Exempted  *policy.Exemption `json:"exempted,omitempty"`
}

// Result is everything one run produced.
type Result struct {
	Policy       policy.Policy    `json:"-"`
	PolicySource string           `json:"policy_source"`
	Inventory    supply.Inventory `json:"-"`
	Components   int              `json:"components"`
	Violations   []Violation      `json:"violations"`
	Notes        []string         `json:"notes,omitempty"`
	FeedVersion  string           `json:"feed_version,omitempty"`
	LockWritten  string           `json:"lock_written,omitempty"`
}

// Failed reports whether any unwaived error-level violation was found.
func (r Result) Failed() bool {
	for _, v := range r.Violations {
		if v.Level == policy.Error && v.Exempted == nil {
			return true
		}
	}
	return false
}

// Counts returns how many violations sit at each level, waivers excluded.
func (r Result) Counts() (errors, warnings, waived int) {
	for _, v := range r.Violations {
		switch {
		case v.Exempted != nil:
			waived++
		case v.Level == policy.Error:
			errors++
		case v.Level == policy.Warn:
			warnings++
		}
	}
	return
}

// Run inventories the repository and applies its policy.
func Run(opt Options) (Result, error) {
	dir := opt.Dir
	if dir == "" {
		dir = "."
	}
	policyPath := opt.PolicyPath
	if policyPath == "" {
		policyPath = filepath.Join(dir, policy.FileName)
	}
	lockPath := opt.LockPath
	if lockPath == "" {
		lockPath = filepath.Join(dir, policy.LockFileName)
	}

	pol, err := policy.Load(policyPath)
	if err != nil {
		return Result{}, err
	}

	// Detection patterns live in the signed feed, so they must be installed
	// before the repository is inventoried.
	ruleCount, ruleNotes := installRules(opt)

	inv, err := supply.TakeProject(dir)
	if err != nil {
		return Result{}, err
	}

	res := Result{
		Policy: pol, PolicySource: pol.Source,
		Inventory: inv, Components: len(inv.Artifacts),
	}
	res.Notes = append(res.Notes, inv.Skipped...)
	res.Notes = append(res.Notes, ruleNotes...)
	res.Violations = append(res.Violations, unevaluableRules(pol, ruleCount, opt)...)

	for _, e := range pol.ExpiredExemptions() {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"An exemption for rule %q expired on %s and is no longer suppressing anything: %s",
			e.Rule, e.Expires, e.Reason))
	}

	res.Violations = append(res.Violations, indicatorViolations(pol, inv)...)
	res.Violations = append(res.Violations, unpinnedViolations(pol, inv)...)

	if !opt.NoFeed {
		hits, version, note := feedViolations(pol, inv, opt.FeedPath)
		res.Violations = append(res.Violations, hits...)
		res.FeedVersion = version
		if note != "" {
			res.Notes = append(res.Notes, note)
		}
	}

	lock, lockErr := policy.LoadLock(lockPath)
	switch {
	case lockErr == policy.ErrNoLock:
		res.Notes = append(res.Notes, fmt.Sprintf(
			"No %s in this repository, so drift cannot be detected. Create one with: aiexpose ci --write-lock",
			policy.LockFileName))
	case lockErr != nil:
		return res, lockErr
	default:
		res.Violations = append(res.Violations, lockViolations(pol, inv, lock)...)
	}

	if opt.WriteLock {
		if err := policy.SaveLock(lockPath, policy.NewLock(inv)); err != nil {
			return res, err
		}
		res.LockWritten = lockPath
	}

	sort.SliceStable(res.Violations, func(i, j int) bool {
		return levelRank(res.Violations[i]) < levelRank(res.Violations[j])
	})
	return res, nil
}

// unevaluableRules reports a gate that cannot check what it was asked to check.
//
// Without this, a CI job whose rule file failed to download reports a green
// tick: the rules that matter most simply produce no findings, and the pull
// request merges as if it had been reviewed. A gate that could not evaluate its
// own policy must say so, and at the level the policy asked for.
func unevaluableRules(pol policy.Policy, ruleCount int, opt Options) []Violation {
	if opt.NoFeed || ruleCount > 0 {
		return nil
	}
	worst := policy.Ignore
	var blocked []string
	for _, rule := range []policy.Rule{policy.RiskIndicator, policy.KnownBad} {
		level := pol.LevelFor(rule)
		if level == policy.Ignore {
			continue
		}
		blocked = append(blocked, string(rule))
		if level == policy.Error || worst == policy.Ignore {
			worst = level
		}
	}
	if len(blocked) == 0 {
		return nil
	}
	return []Violation{{
		Rule:  policy.RiskIndicator,
		Level: worst,
		Title: "The gate could not check for malicious code",
		Detail: "No detection rules were loaded, so " + strings.Join(blocked, " and ") +
			" could not be evaluated and this result does not mean the repository is clean.\n" +
			"Install the rules in the job before running the gate:\n  aiexpose --update-feed\n" +
			"or commit a signed rule file and pass: aiexpose ci --feed rules.json",
		Component: "aiexpose",
	}}
}

// installRules loads detection patterns from the signed feed for this run.
func installRules(opt Options) (int, []string) {
	if opt.NoFeed {
		supply.SetIndicatorRules(nil)
		return 0, nil
	}
	f, err := feed.Load(opt.FeedPath)
	if err != nil {
		supply.SetIndicatorRules(nil)
		return 0, []string{"Detection patterns could not be loaded: " + err.Error()}
	}
	specs := make([]supply.RuleSpec, 0, len(f.Indicators))
	for _, ind := range f.Indicators {
		specs = append(specs, supply.RuleSpec{
			ID: ind.ID, Title: ind.Title,
			Severity: ind.SeverityLevel(), Pattern: ind.Pattern,
		})
	}
	var notes []string
	for _, msg := range supply.SetIndicatorRules(specs) {
		notes = append(notes, "A detection pattern was skipped because it does not compile - "+msg)
	}
	return supply.IndicatorRuleCount(), notes
}

func levelRank(v Violation) int {
	switch {
	case v.Exempted != nil:
		return 3
	case v.Level == policy.Error:
		return 0
	case v.Level == policy.Warn:
		return 1
	}
	return 2
}

// add builds a violation unless the rule is ignored, marking it waived when an
// exemption applies. Waived violations are still reported, so a review can see
// what the policy is currently letting through.
func add(pol policy.Policy, rule policy.Rule, s policy.Subject, v Violation) (Violation, bool) {
	level := pol.LevelFor(rule)
	if level == policy.Ignore {
		return Violation{}, false
	}
	v.Rule, v.Level = rule, level
	v.Component = s.Component
	if e, ok := pol.Exempt(rule, s); ok {
		v.Exempted = &e
	}
	return v, true
}

func indicatorViolations(pol policy.Policy, inv supply.Inventory) []Violation {
	var out []Violation
	for _, a := range inv.Artifacts {
		for _, ind := range a.Indicators {
			s := policy.Subject{Component: a.Name, Package: a.Detail["package"], Path: a.Path}
			v, ok := add(pol, policy.RiskIndicator, s, Violation{
				Title:  fmt.Sprintf("%s: %s", a.Name, ind.Title),
				Detail: fmt.Sprintf("[%s] %s\n%s", ind.ID, ind.Title, ind.Excerpt),
				Path:   ind.File, Line: ind.Line,
			})
			if ok {
				out = append(out, v)
			}
		}
	}
	return out
}

func unpinnedViolations(pol policy.Policy, inv supply.Inventory) []Violation {
	var out []Violation
	for _, a := range inv.Artifacts {
		pkg := a.Detail["unpinned"]
		if pkg == "" {
			continue
		}
		s := policy.Subject{Component: a.Name, Package: a.Detail["package"], Path: a.Path}
		v, ok := add(pol, policy.UnpinnedPackage, s, Violation{
			Title: fmt.Sprintf("MCP server %q runs an unpinned package (%s)", a.Name, pkg),
			Detail: "This server fetches and executes whatever the registry serves at launch, so the code reviewed in this pull request is not necessarily the code that runs. " +
				"Pin an exact version, for example " + pkg + "@1.4.2.",
			Path: a.Detail["config"],
		})
		if ok {
			out = append(out, v)
		}
	}
	return out
}

func feedViolations(pol policy.Policy, inv supply.Inventory, feedPath string) ([]Violation, string, string) {
	f, err := feed.Load(feedPath)
	if err != nil {
		return nil, "", "Known-bad component list could not be loaded: " + err.Error()
	}

	components := make([]feed.Component, 0, len(inv.Artifacts))
	byName := map[string]supply.Artifact{}
	for _, a := range inv.Artifacts {
		byName[a.Name] = a
		components = append(components, feed.Component{
			Kind: a.Kind, Name: a.Name, Path: a.Path,
			Digest: a.Digest, FileDigests: a.FileDigests,
			Package: a.Detail["package"], Version: a.Detail["package_version"],
		})
	}

	var out []Violation
	for _, h := range f.Match(components) {
		s := policy.Subject{Component: h.Component.Name, Package: h.Component.Package, Path: h.Component.Path}
		v, ok := add(pol, policy.KnownBad, s, Violation{
			Title:  h.Entry.Title,
			Detail: h.Entry.Detail + "\nMatched because " + h.Why + ".\nList entry: " + h.Entry.ID,
			Path:   h.Component.Path, Ref: h.Entry.Ref,
		})
		if ok {
			out = append(out, v)
		}
	}

	note := ""
	if f.Stale() {
		note = fmt.Sprintf("The known-bad component list is %d days old (version %s); refresh it in CI with: aiexpose --update-feed",
			int(f.Age().Hours()/24), f.Version)
	}
	return out, f.Version, note
}

func lockViolations(pol policy.Policy, inv supply.Inventory, lock policy.Lock) []Violation {
	locked := lock.Index()
	var out []Violation

	for _, a := range inv.Artifacts {
		s := policy.Subject{Component: a.Name, Package: a.Detail["package"], Path: a.Path}
		prev, known := locked[a.ID]
		if !known {
			v, ok := add(pol, policy.Unlocked, s, Violation{
				Title: fmt.Sprintf("%s %q is not in %s", a.Kind, a.Name, policy.LockFileName),
				Detail: "This component was added without being recorded as reviewed. " +
					"Once you have reviewed it, run: aiexpose ci --write-lock",
				Path: a.Path,
			})
			if ok {
				out = append(out, v)
			}
			continue
		}
		if prev.Digest != a.Digest {
			detail := fmt.Sprintf("The locked digest is %s and the current contents hash to %s.",
				short(prev.Digest), short(a.Digest))
			if prev.Spec != "" && prev.Spec != a.Detail["spec"] {
				detail = fmt.Sprintf("The launch command changed from %q to %q.", prev.Spec, a.Detail["spec"])
			}
			v, ok := add(pol, policy.LockDrift, s, Violation{
				Title:  fmt.Sprintf("%s %q changed since it was reviewed", a.Kind, a.Name),
				Detail: detail + "\nRe-review it, then run: aiexpose ci --write-lock",
				Path:   a.Path,
			})
			if ok {
				out = append(out, v)
			}
		}
	}
	return out
}

func short(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}
