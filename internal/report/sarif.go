package report

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/MC-kakadu/AIexpose/internal/ci"
	"github.com/MC-kakadu/AIexpose/internal/policy"
)

// SARIF is the interchange format code-scanning platforms read. Emitting it is
// what puts a finding on the changed line of a pull request instead of in a log
// nobody opens.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string           `json:"id"`
	Name                 string           `json:"name"`
	ShortDescription     sarifText        `json:"shortDescription"`
	FullDescription      sarifText        `json:"fullDescription"`
	HelpURI              string           `json:"helpUri,omitempty"`
	DefaultConfiguration sarifRuleDefault `json:"defaultConfiguration"`
}

type sarifRuleDefault struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

var ruleDescriptions = map[policy.Rule]string{
	policy.KnownBad:        "A component matches the signed list of packages and nodes already documented as malicious.",
	policy.RiskIndicator:   "A component's source contains credential theft, data exfiltration, obfuscated execution or persistence.",
	policy.UnpinnedPackage: "An MCP server launches a registry package without a pinned version, so the code that runs is not the code that was reviewed.",
	policy.LockDrift:       "A component's contents changed after it was recorded as reviewed.",
	policy.Unlocked:        "A component is present that the committed lockfile does not record as reviewed.",
}

// SARIF writes the CI result in SARIF 2.1.0.
func SARIF(w io.Writer, res ci.Result, toolName, version string) error {
	rules := make([]sarifRule, 0, len(policy.AllRules))
	for _, r := range policy.AllRules {
		rules = append(rules, sarifRule{
			ID:               string(r),
			Name:             string(r),
			ShortDescription: sarifText{Text: ruleDescriptions[r]},
			FullDescription:  sarifText{Text: ruleDescriptions[r]},
			DefaultConfiguration: sarifRuleDefault{
				Level: sarifLevel(res.Policy.LevelFor(r)),
			},
		})
	}

	results := make([]sarifResult, 0, len(res.Violations))
	for _, v := range res.Violations {
		// A waived violation is reported as a note, never dropped: a reviewer
		// should still be able to see what the policy is letting through.
		level := sarifLevel(v.Level)
		message := v.Title + "\n" + v.Detail
		if v.Exempted != nil {
			level = "note"
			message = "[exempted] " + message + "\nExemption reason: " + v.Exempted.Reason
		}
		r := sarifResult{RuleID: string(v.Rule), Level: level, Message: sarifText{Text: message}}
		if v.Path != "" {
			loc := sarifLocation{PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{URI: v.Path},
			}}
			if v.Line > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: v.Line}
			}
			r.Locations = append(r.Locations, loc)
		}
		results = append(results, r)
	}
	sort.SliceStable(results, func(i, j int) bool { return results[i].RuleID < results[j].RuleID })

	doc := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: toolName, Version: version, Rules: rules}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// sarifLevel maps a policy level onto SARIF's vocabulary.
func sarifLevel(l policy.Level) string {
	switch l {
	case policy.Error:
		return "error"
	case policy.Warn:
		return "warning"
	}
	return "none"
}
