package checks

import (
	"github.com/MC-kakadu/AIexpose/internal/feed"
	"github.com/MC-kakadu/AIexpose/internal/model"
	"github.com/MC-kakadu/AIexpose/internal/supply"
)

// RulesLoaded reports how many detection rules of each kind are active.
type RulesLoaded struct {
	Indicators  int
	Credentials int
	FeedVersion string
	FeedOrigin  string
}

// noRules records that this scan could not look for malicious code.
//
// This is a finding rather than a footnote on purpose. A scan with no rules
// still produces a report full of green ticks, and a reader who skims it will
// conclude their machine is clean when the most important check never ran.
func noRules(r *model.Report, why string) {
	r.Add(model.Finding{
		ID:       "RULE-001",
		Title:    "This scan did not check for malicious code",
		Severity: model.Medium,
		Advisory: true,
		Detail: "No detection rules were loaded, so installed components were not inspected for " +
			"credential theft or data exfiltration, and no scan for plaintext API keys was performed. " +
			"Everything else in this report still ran.\n" + why,
		Fix: "Install the rules once. They ship beside the binary in a release, and inside the " +
			"repository at " + repoRulesPath + " if you built from source.",
		Command: selfCommand("--install-rules " + rulesFileToSuggest()),
	})
}

// LoadRules installs the detection patterns from the signed feed.
//
// Several checks depend on these, so loading happens once, before any of them
// run, and independently of which checks are enabled. Tying it to one check
// would mean disabling that check silently disarmed the others.
func LoadRules(r *model.Report, feedPath string, disabled bool) RulesLoaded {
	if disabled {
		supply.SetIndicatorRules(nil)
		SetCredentialRules(CredentialRules{})
		r.Note("Detection rules not loaded (--no-feed): component source and credential scans were skipped.")
		return RulesLoaded{}
	}

	f, err := feed.Load(feedPath)
	if err != nil {
		supply.SetIndicatorRules(nil)
		SetCredentialRules(CredentialRules{})
		noRules(r, "The rule file could not be read: "+err.Error()+
			"\nIf it was there before, your antivirus may have quarantined it: the rules are a list "+
			"of what malicious code looks like, which some scanners flag on sight. See ANTIVIRUS.md.")
		return RulesLoaded{}
	}

	specs := make([]supply.RuleSpec, 0, len(f.Indicators))
	for _, ind := range f.Indicators {
		specs = append(specs, supply.RuleSpec{
			ID: ind.ID, Title: ind.Title,
			Severity: ind.SeverityLevel(), Pattern: ind.Pattern,
		})
	}
	for _, msg := range supply.SetIndicatorRules(specs) {
		r.Note("A detection pattern was skipped because it does not compile - " + msg)
	}

	if f.Credentials != nil {
		patterns := make([]CredentialPattern, 0, len(f.Credentials.Patterns))
		for _, p := range f.Credentials.Patterns {
			patterns = append(patterns, CredentialPattern{Vendor: p.Vendor, Pattern: p.Pattern})
		}
		for _, msg := range SetCredentialRules(CredentialRules{
			Patterns:     patterns,
			HistoryFiles: f.Credentials.HistoryFiles,
			ConfigFiles:  f.Credentials.ConfigFiles,
			SearchDirs:   f.Credentials.SearchDirs,
			SearchNames:  f.Credentials.SearchNames,
			SearchExts:   f.Credentials.SearchExts,
			DocDirs:      f.Credentials.DocDirs,
			SkipDirs:     f.Credentials.SkipDirs,
		}) {
			r.Note("A credential pattern was skipped because it does not compile - " + msg)
		}
	} else {
		SetCredentialRules(CredentialRules{})
	}

	loaded := RulesLoaded{
		Indicators: supply.IndicatorRuleCount(), Credentials: CredentialRuleCount(),
		FeedVersion: f.Version, FeedOrigin: f.Origin,
	}
	if loaded.Indicators == 0 && loaded.Credentials == 0 {
		noRules(r, "This build ships without them ("+f.Origin+").")
	}
	return loaded
}
