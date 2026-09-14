package checks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MC-kakadu/AIexpose/internal/feed"
	"github.com/MC-kakadu/AIexpose/internal/model"
)

// These five came off a real machine. They are entries in a skill catalogue
// written in Markdown, and the report told their owner to rotate all five at
// the provider. Nothing here is a credential.
var realWorldFalsePositives = []string{
	"sk-contract-review-dashboard",
	"sk-delivery-tracking-service",
	"sk-finance-ledger-accounts",
	"sk-internal-comms-journal",
	"sk-tax-filing-reporting",
	// The same shape in the other loose patterns.
	"xoxb-order-status-webhook-handler",
	"sk-ant-customer-support-router",
	"hf_deploymentpipelinestagingcluster",
}

// shaped builds a fixture that looks like a credential without any source
// file containing one.
//
// This is not fussiness. A test corpus for a credential detector has to hold
// realistic key shapes, and a realistic key shape is exactly what every other
// secret scanner in the world is looking for. One Slack bot token shape,
// written here as a single literal, got a push to GitHub rejected by its
// secret scanning: our test fixture was somebody else's incident. Assembling
// the prefix from pieces means no scanner, ours included, can match a run of
// bytes that exists in this file -- and note that this comment describes the
// shape rather than quoting it, for the same reason.
func shaped(prefix, body string) string { return prefix + body }

// Genuine key shapes. Any of these going missing is the cost of getting the
// false positives above wrong, and it is a cost this project will not pay
// silently.
var realKeyShapes = []string{
	shaped("sk"+"-", strings.Repeat("A7bQ", 12)),
	shaped("sk"+"-proj-", strings.Repeat("aB3_", 15)+"xYz9"),
	shaped("sk"+"-svcacct-", strings.Repeat("Kp9-", 12)+"Qm2"),
	shaped("sk"+"-ant-api03-", strings.Repeat("Zx4_", 12)+"Ab7"),
	shaped("gh"+"p_", strings.Repeat("a1B2", 9)),
	shaped("h"+"f_", strings.Repeat("aB1c", 8)),
	shaped("gs"+"k_", strings.Repeat("Xy7Z", 10)),
	shaped("AK"+"IA", strings.Repeat("AB12", 4)),
	shaped("xo"+"xb-", "2314567890-98765432109-"+strings.Repeat("Ab7Z", 4)),
	shaped("r"+"8_", strings.Repeat("q2W9", 8)),
}

// shippedFeed reads the rule document that is released to users.
//
// It is read from the repository rather than from feed.Builtin(), because the
// default build deliberately embeds no rules -- that is the whole point of the
// v0.8 change. A test that skipped when the rules were absent would pass on
// every default build while proving nothing, which is the same silent pass
// this scanner has had to fix in its own output more than once.
func shippedFeed(t *testing.T) feed.Feed {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "feed", "data", "feed.json"))
	if err != nil {
		t.Fatalf("the shipped rule file could not be read: %v", err)
	}
	var f feed.Feed
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("the shipped rule file does not parse: %v", err)
	}
	if f.Credentials == nil || len(f.Credentials.Patterns) == 0 {
		t.Fatal("the shipped rule file carries no credential patterns")
	}
	return f
}

// loadShippedRules uses the rules that actually ship, not a copy. A test
// against a hand-written pattern proves nothing about what users run.
func loadShippedRules(t *testing.T) {
	t.Helper()
	f := shippedFeed(t)
	pats := make([]CredentialPattern, 0, len(f.Credentials.Patterns))
	for _, p := range f.Credentials.Patterns {
		pats = append(pats, CredentialPattern{Vendor: p.Vendor, Pattern: p.Pattern})
	}
	prev := keyPatterns
	t.Cleanup(func() { keyPatterns = prev })
	if bad := SetCredentialRules(CredentialRules{Patterns: pats}); len(bad) > 0 {
		t.Fatalf("shipped patterns do not compile: %v", bad)
	}
}

func TestDocumentIdentifiersAreNotReportedAsKeys(t *testing.T) {
	loadShippedRules(t)
	for _, s := range realWorldFalsePositives {
		if hits := scanLine("catalogue.md", 1, s); len(hits) > 0 {
			t.Errorf("%q was reported as a %s key (masked %s)", s, hits[0].vendor, hits[0].masked)
		}
	}
}

func TestRealKeyShapesAreStillFound(t *testing.T) {
	loadShippedRules(t)
	for _, s := range realKeyShapes {
		if hits := scanLine("notes.txt", 1, "token = "+s); len(hits) == 0 {
			t.Errorf("%q is no longer detected", s)
		}
	}
}

// The shape test on its own, so a future pattern change cannot quietly
// re-open the hole by widening a character class.
func TestKeyMaterialShape(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"sk-contract-review-dashboard", false},
		{"sk-proj-all-lower-case-words-joined-with-hyphens-here", false},
		{"xoxb-order-status-webhook", false},
		{"sk-" + strings.Repeat("A7bQ", 12), true},
		{"sk-" + strings.Repeat("abcd", 12) + "1", true}, // one digit is enough
		{"sk-" + strings.Repeat("abcd", 12) + "Z", true}, // one capital is enough
		{"hf_" + strings.Repeat("abcdefgh", 4), false},   // prefix has a digit-free body
		{"AKIA" + strings.Repeat("AB12", 4), true},
	}
	for _, c := range cases {
		if got := looksLikeKeyMaterial(c.in); got != c.want {
			t.Errorf("looksLikeKeyMaterial(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// The prefix must not vouch for the body: "AIza" carries a capital, and if it
// counted, every lowercase string behind it would pass.
func TestPrefixDoesNotVouchForBody(t *testing.T) {
	if looksLikeKeyMaterial("AIza" + strings.Repeat("abcdefg", 5)) {
		t.Error("the capital in the AIza prefix was counted as key material")
	}
	if looksLikeKeyMaterial("sk-ant-api03-" + strings.Repeat("abcdefg", 6)) {
		t.Error("the digits in the api03 prefix were counted as key material")
	}
}

// End to end, through the file walk, on the exact document shape that failed.
func TestCatalogueFileProducesNoFinding(t *testing.T) {
	loadShippedRules(t)
	f := shippedFeed(t)
	searchExts = []string{".md", ".txt"}
	docDirs, skipDirs, aiDirs, aiFileNames, configFiles, historyFiles = nil, nil, nil, nil, nil, nil
	if f.Credentials != nil {
		searchExts = f.Credentials.SearchExts
	}
	t.Cleanup(func() { SetCredentialRules(CredentialRules{}) })

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	body := "# Skill catalogue\n"
	for i, s := range realWorldFalsePositives {
		body += "- " + s + "  (entry " + string(rune('a'+i)) + ")\n"
	}
	if err := os.WriteFile(filepath.Join(home, "catalogue.md"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	r := &model.Report{}
	Secrets(r, SecretScope{})
	for _, fi := range r.Findings {
		if fi.ID == "SEC-002" {
			t.Fatalf("a skill catalogue produced a credential finding:\n%s", strings.Join(fi.Evidence, "\n"))
		}
	}
}
