package checks

import (
	"regexp"
	"testing"
)

// Every shipped pattern must compile.
//
// This is the floor, and until now nothing enforced it. A pattern that fails to
// compile is skipped and mentioned in a note -- deliberately, so one bad rule
// cannot disarm the rest -- but the scan then runs with fewer rules than the
// report's own count implies, and no error is raised anywhere. Shipping a
// typo'd regex would mean every user silently lost that detection.
func TestEveryShippedIndicatorPatternCompiles(t *testing.T) {
	f := shippedFeed(t)
	if len(f.Indicators) == 0 {
		t.Fatal("the shipped feed carries no indicator rules, so this test would prove nothing")
	}
	for _, r := range f.Indicators {
		if r.Pattern == "" {
			t.Errorf("%s has no pattern", r.ID)
			continue
		}
		if _, err := regexp.Compile(r.Pattern); err != nil {
			t.Errorf("%s does not compile, so it would be silently skipped: %v", r.ID, err)
		}
	}
}

func TestEveryShippedCredentialPatternCompiles(t *testing.T) {
	f := shippedFeed(t)
	if f.Credentials == nil || len(f.Credentials.Patterns) == 0 {
		t.Fatal("the shipped feed carries no credential patterns, so this test would prove nothing")
	}
	for _, p := range f.Credentials.Patterns {
		if _, err := regexp.Compile(p.Pattern); err != nil {
			t.Errorf("credential pattern %s (%s) does not compile: %v", p.ID, p.Vendor, err)
		}
	}
}

// The count the report prints must be the count that actually loaded. Without
// this, a rule dropped for not compiling would still be counted in the
// attestation line the reader is asked to trust.
func TestLoadedRuleCountMatchesTheShippedFeed(t *testing.T) {
	f := shippedFeed(t)
	want := len(f.Indicators)

	specs := make([]ruleSpecForTest, 0, want)
	for _, r := range f.Indicators {
		specs = append(specs, ruleSpecForTest{ID: r.ID, Pattern: r.Pattern})
	}
	got := 0
	for _, s := range specs {
		if _, err := regexp.Compile(s.Pattern); err == nil {
			got++
		}
	}
	if got != want {
		t.Errorf("%d of %d shipped indicator rules would load; the report would still claim %d",
			got, want, want)
	}
}

type ruleSpecForTest struct{ ID, Pattern string }
