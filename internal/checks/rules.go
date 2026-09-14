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
	staleRuleFile(r, f)
	return loaded
}

// staleRuleFile reports a rule file older than the one this build was
// published with.
//
// This exists because of a failure that produced no error anywhere. A release
// shipped with fourteen known-bad entries; the machine still had the previous
// release's three-entry rule file sitting beside the binary. It verified
// against the compiled-in key, so it loaded, and the report said "No installed
// component appears on the known-bad list (3 entries)" -- signed, correct, and
// eleven entries short of what that binary was published with. A signature
// proves who wrote a file, never that it is the current one.
//
// It is Advisory: the reader's machine is not more exposed because their rule
// file is old, so the grade does not move, but the report is not complete
// either and must not be read as though it were.
func staleRuleFile(r *model.Report, f feed.Feed) {
	behind, have, want := f.BehindRelease()
	if !behind {
		return
	}
	r.Add(model.Finding{
		ID:       "RULE-002",
		Title:    "The detection rules are older than this release",
		Severity: model.Low,
		Advisory: true,
		Detail: "This scan used rule version " + have + ", but this build of aiexpose was published " +
			"alongside version " + want + ". Everything the older rules describe was checked; whatever " +
			"was added since was not, so anything found -- and anything not found -- reflects the older " +
			"list.\n\n" +
			"The usual cause is an aiexpose-rules.json left beside the binary from a previous download. " +
			"It still carries a valid signature, which is why nothing complained: a signature says who " +
			"wrote a file, not whether it is the current one.\n" +
			"Loaded from: " + f.Origin + ".",
		Fix: "Replace the rule file beside the binary with the one published for this release, or " +
			"fetch the newest rules directly:",
		Command: selfCommand("--update-feed"),
	})
}
