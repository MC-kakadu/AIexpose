package checks

import "testing"

// testCredentialRules mirrors the ordering the signed feed ships: more
// specific prefixes first, so sk-ant- never falls through to the OpenAI rule.
func testCredentialRules(t *testing.T) {
	t.Helper()
	skipped := SetCredentialRules(CredentialRules{Patterns: []CredentialPattern{
		{Vendor: "Anthropic", Pattern: `sk-ant-[A-Za-z0-9_\-]{20,}`},
		{Vendor: "OpenAI", Pattern: `sk-(?:proj-)?[A-Za-z0-9_\-]{20,}`},
		{Vendor: "AWS", Pattern: `AKIA[0-9A-Z]{16}`},
		{Vendor: "Hugging Face", Pattern: `hf_[A-Za-z0-9]{30,}`},
	}})
	if len(skipped) != 0 {
		t.Fatalf("test patterns did not compile: %v", skipped)
	}
	t.Cleanup(func() { SetCredentialRules(CredentialRules{}) })
}

// With no patterns loaded the scanner must find nothing rather than panic.
func TestNoCredentialRulesMeansNoHits(t *testing.T) {
	SetCredentialRules(CredentialRules{})
	if hits := scanLine("/tmp/x", 1, "AK"+"IAIOSFODNN7EXAMPLE"); len(hits) != 0 {
		t.Fatalf("got %+v with no rules loaded, want none", hits)
	}
}

// A single Anthropic key also satisfies the broader OpenAI prefix rule.
// It must be reported exactly once, attributed to the more specific vendor.
func TestScanLineNoDuplicateVendors(t *testing.T) {
	testCredentialRules(t)
	line := `curl -H "Authorization: Bearer sk-ant-api03-QQQwwweeerrrtttyyyuuuiiiooo111222333"`
	hits := scanLine("/tmp/x", 1, line)
	if len(hits) != 1 {
		t.Fatalf("got %d hits, want 1: %+v", len(hits), hits)
	}
	if hits[0].vendor != "Anthropic" {
		t.Errorf("vendor = %q, want Anthropic", hits[0].vendor)
	}
}

func TestScanLineMasksValue(t *testing.T) {
	testCredentialRules(t)
	// Split so this file contains no run of bytes that a secret scanner --
	// ours, GitHub's, or a contributor's pre-commit hook -- will match.
	secret := "sk" + "-proj-AbCdEf1234567890QwErTyUiOpAsDfGhJk"
	hits := scanLine("/tmp/x", 1, "OPENAI_API_KEY="+secret)
	if len(hits) != 1 {
		t.Fatalf("got %d hits, want 1", len(hits))
	}
	if hits[0].masked == secret {
		t.Fatal("secret was reported verbatim")
	}
	if len(hits[0].masked) == 0 || hits[0].masked[:6] != secret[:6] {
		t.Errorf("masked = %q, want a short prefix of the original", hits[0].masked)
	}
}

func TestScanLineMultipleDistinctKeys(t *testing.T) {
	testCredentialRules(t)
	// The Hugging Face token here used to be a run of the letter "a". That is
	// not a shape any token generator produces, and since v0.19.2 a match with
	// no digit and no capital anywhere is rejected as not being key material --
	// the rule that stopped a skill catalogue's identifiers being reported as
	// five OpenAI keys. A realistic token is the right fixture.
	line := "AK" + "IAIOSFODNN7EXAMPLE and " + "h" + "f_QZdKp2mVnB7xLtR4wYs9Ag3JhE6cUf1Nki"
	if hits := scanLine("/tmp/x", 1, line); len(hits) != 2 {
		t.Fatalf("got %d hits, want 2: %+v", len(hits), hits)
	}
}

func TestScanLineClean(t *testing.T) {
	testCredentialRules(t)
	if hits := scanLine("/tmp/x", 1, "echo hello world"); len(hits) != 0 {
		t.Fatalf("false positive on benign line: %+v", hits)
	}
}

func TestNonLoopbackValue(t *testing.T) {
	safe := []string{"127.0.0.1", "127.0.0.1:11434", "localhost:8080", "::1", "[::1]:8080", ""}
	risky := []string{"0.0.0.0", "0.0.0.0:11434", "192.168.1.5:8080", "example.local"}
	for _, v := range safe {
		if nonLoopbackValue(v) {
			t.Errorf("nonLoopbackValue(%q) = true, want false", v)
		}
	}
	for _, v := range risky {
		if !nonLoopbackValue(v) {
			t.Errorf("nonLoopbackValue(%q) = false, want true", v)
		}
	}
}
