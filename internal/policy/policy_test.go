package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultsAreUsedWhenNoFileExists(t *testing.T) {
	p, err := Load(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatalf("a missing policy file must fall back to defaults, got %v", err)
	}
	if p.LevelFor(KnownBad) != Error {
		t.Errorf("known_bad default = %q, want error", p.LevelFor(KnownBad))
	}
	// Adding the gate to an existing repository should not break its build on
	// day one, so the softer rules only warn.
	if p.LevelFor(UnpinnedPackage) != Warn {
		t.Errorf("unpinned_package default = %q, want warn", p.LevelFor(UnpinnedPackage))
	}
}

func TestLoadRejectsUnknownRulesAndLevels(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"unknown rule":  `{"version":1,"rules":{"no_such_rule":"error"}}`,
		"unknown level": `{"version":1,"rules":{"known_bad":"maybe"}}`,
		"future schema": `{"version":99}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".json")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Error("a malformed policy must be an error, not silently ignored")
			}
		})
	}
}

func TestExemptionMatching(t *testing.T) {
	future := time.Now().AddDate(1, 0, 0).Format("2006-01-02")
	past := time.Now().AddDate(-1, 0, 0).Format("2006-01-02")

	p := Default()
	p.Exemptions = []Exemption{
		{Rule: UnpinnedPackage, Match: Match{Component: "weather"}, Reason: "mirrored", Expires: future},
		{Rule: UnpinnedPackage, Match: Match{Package: "old-mcp"}, Reason: "lapsed", Expires: past},
		{Rule: KnownBad, Match: Match{Path: "vendor/"}, Reason: "vendored fixture"},
		{Rule: RiskIndicator, Match: Match{}, Reason: "blanket"},
	}

	cases := []struct {
		name string
		rule Rule
		subj Subject
		want bool
	}{
		{"matches by component", UnpinnedPackage, Subject{Component: "weather"}, true},
		{"wrong component", UnpinnedPackage, Subject{Component: "other"}, false},
		{"wrong rule", KnownBad, Subject{Component: "weather"}, false},
		{"expired exemption does not apply", UnpinnedPackage, Subject{Package: "old-mcp"}, false},
		{"path prefix", KnownBad, Subject{Path: "vendor/thing"}, true},
		{"path outside prefix", KnownBad, Subject{Path: "src/thing"}, false},
		// A waiver with no selector must not become a blanket suppression.
		{"empty match is not a wildcard", RiskIndicator, Subject{Component: "anything"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, ok := p.Exempt(c.rule, c.subj); ok != c.want {
				t.Errorf("Exempt(%q, %+v) = %v, want %v", c.rule, c.subj, ok, c.want)
			}
		})
	}

	expired := p.ExpiredExemptions()
	if len(expired) != 1 || expired[0].Reason != "lapsed" {
		t.Errorf("ExpiredExemptions = %+v, want the one lapsed waiver", expired)
	}
}

func TestIgnoreSuppressesEntirely(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	if err := os.WriteFile(path, []byte(`{"version":1,"rules":{"unpinned_package":"ignore"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.LevelFor(UnpinnedPackage) != Ignore {
		t.Errorf("level = %q, want ignore", p.LevelFor(UnpinnedPackage))
	}
	if p.LevelFor(KnownBad) != Error {
		t.Errorf("unmentioned rules keep their default, got %q", p.LevelFor(KnownBad))
	}
}
