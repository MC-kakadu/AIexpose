package feed

import (
	"encoding/json"
	"os"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"1.0.0", "1.0.0", 0, true},
		{"1.0.1", "1.0.0", 1, true},
		{"1.0.0", "1.0.1", -1, true},
		{"1.2", "1.2.0", 0, true},   // missing segments are zero
		{"2.0", "1.99.99", 1, true}, // segments compare numerically, not lexically
		{"8.3.9", "8.3.41", -1, true},
		{"8.3.100", "8.3.99", 1, true},

		// Shapes real registries emit.
		{"v1.2.3", "1.2.3", 0, true},
		{" 1.2.3 ", "1.2.3", 0, true},
		{"1.2.3+build7", "1.2.3", 0, true},
		{"2026.4.0", "2026.3.9", 1, true},

		// A release outranks its own prereleases.
		{"1.2.0", "1.2.0-rc1", 1, true},
		{"1.2.0-rc1", "1.2.0-rc2", -1, true},
		{"1.2.3rc1", "1.2.3", -1, true},

		// Shapes this code will not guess at.
		{"latest", "1.0.0", 0, false},
		{"", "1.0.0", 0, false},
		{"^1.2.3", "1.2.3", 0, false},
		{"1..2", "1.0.2", 0, false},
	}
	for _, c := range cases {
		got, ok := CompareVersions(c.a, c.b)
		if ok != c.ok {
			t.Errorf("CompareVersions(%q, %q) ok = %v, want %v", c.a, c.b, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// The case this whole change exists for. ultralytics 8.3.41 shipped a
// cryptominer; 8.3.40 is the library a hundred thousand people use. An entry
// that cannot tell them apart accuses every clean install.
func TestHijackedVersionsDoNotAccuseCleanInstalls(t *testing.T) {
	e := Entry{
		ID: "T-1", Kind: Package, Match: "ultralytics", Severity: "critical",
		Title:    "compromised releases",
		Versions: []string{"8.3.41", "8.3.42", "8.3.45", "8.3.46"},
	}
	f := Feed{Entries: []Entry{e}}

	affected := []string{"8.3.41", "8.3.42", "8.3.45", "8.3.46"}
	for _, v := range affected {
		hits := f.Match([]Component{{Package: "ultralytics", Version: v}})
		if len(hits) != 1 || hits[0].Unresolved {
			t.Errorf("ultralytics@%s was not reported as affected: %+v", v, hits)
		}
	}
	clean := []string{"8.3.40", "8.3.43", "8.3.44", "8.3.47", "8.4.0", "8.2.0"}
	for _, v := range clean {
		if hits := f.Match([]Component{{Package: "ultralytics", Version: v}}); len(hits) != 0 {
			t.Errorf("ultralytics@%s, a clean release, was reported: %s", v, hits[0].Why)
		}
	}
}

func TestVersionRangeCoversAdvisoryShape(t *testing.T) {
	// "affected from 1.82.7, fixed in 1.82.9" is how advisories are written.
	f := Feed{Entries: []Entry{{
		ID: "T-2", Kind: Package, Match: "litellm", Severity: "critical", Title: "hijacked",
		Ranges: []Range{{Introduced: "1.82.7", Fixed: "1.82.9"}},
	}}}

	for _, v := range []string{"1.82.7", "1.82.8"} {
		if hits := f.Match([]Component{{Package: "litellm", Version: v}}); len(hits) != 1 {
			t.Errorf("litellm@%s should be inside the range", v)
		}
	}
	for _, v := range []string{"1.82.6", "1.82.9", "1.83.0"} {
		if hits := f.Match([]Component{{Package: "litellm", Version: v}}); len(hits) != 0 {
			t.Errorf("litellm@%s should be outside the range, got %q", v, hits[0].Why)
		}
	}
}

// An unpinned spec fetches whatever the registry serves, so it can land on an
// affected version at any moment. It must still be reported, and the reason
// must say that rather than claiming the affected version is installed.
func TestUnpinnedPackageIsStillReported(t *testing.T) {
	f := Feed{Entries: []Entry{{
		ID: "T-3", Kind: Package, Match: "ultralytics", Severity: "critical", Title: "x",
		Versions: []string{"8.3.41"},
	}}}
	hits := f.Match([]Component{{Package: "ultralytics", Version: ""}})
	if len(hits) != 1 {
		t.Fatalf("an unpinned install of a listed package was not reported")
	}
	if hits[0].Unresolved {
		t.Error("an unpinned install is a definite finding, not an unresolved one")
	}
	if !contains(hits[0].Why, "unpinned") || !contains(hits[0].Why, "8.3.41") {
		t.Errorf("the reason does not explain itself: %q", hits[0].Why)
	}
}

// The third state. A version that cannot be compared must not be silently
// dropped (which would turn a known-bad package into a clean result) and must
// not be reported as a confirmed match (which would invent the half that was
// never established).
func TestUncomparableVersionIsUnresolvedNotSilent(t *testing.T) {
	f := Feed{Entries: []Entry{{
		ID: "T-4", Kind: Package, Match: "litellm", Severity: "critical", Title: "x",
		Versions: []string{"1.82.7"},
	}}}
	hits := f.Match([]Component{{Package: "litellm", Version: "latest"}})
	if len(hits) != 1 {
		t.Fatalf("an uncomparable version was dropped silently; got %d hits", len(hits))
	}
	if !hits[0].Unresolved {
		t.Error("an uncomparable version was reported as a confirmed match")
	}
}

func TestEntryWithNoConstraintsCoversEveryVersion(t *testing.T) {
	f := Feed{Entries: []Entry{{ID: "T-5", Kind: Package, Match: "postmark-mcp", Severity: "critical", Title: "x"}}}
	for _, v := range []string{"1.0.0", "1.0.18", "", "latest"} {
		hits := f.Match([]Component{{Package: "postmark-mcp", Version: v}})
		if len(hits) != 1 || hits[0].Unresolved {
			t.Errorf("a pulled package must match every version, %q did not: %+v", v, hits)
		}
	}
}

func contains(h, n string) bool { return len(h) >= len(n) && (len(n) == 0 || indexOf(h, n) >= 0) }

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}

// --- validation ---------------------------------------------------------

// The bug this check was written for: a version constraint on a kind that has
// no version to compare is thrown away, and the entry then matches every
// install instead of the affected ones.
func TestValidateCatchesConstraintsOnKindThatIgnoresThem(t *testing.T) {
	f := Feed{Entries: []Entry{{
		ID: "T-6", Kind: NodeName, Match: "some-node", Severity: "critical", Title: "x",
		Versions: []string{"1.0.0"},
	}}}
	probs := f.Validate()
	if len(probs) == 0 {
		t.Fatal("version constraints on a node-name entry were accepted")
	}
	// And the matcher's behaviour is what the message says it is.
	hits := f.Match([]Component{{Name: "some-node", Version: "9.9.9"}})
	if len(hits) != 1 {
		t.Error("the node-name entry did not match a version outside its own constraint list, " +
			"so the validation message is now wrong")
	}
}

func TestValidateCatchesUnusableEntries(t *testing.T) {
	cases := []struct {
		name  string
		entry Entry
	}{
		{"unparseable version", Entry{ID: "a", Kind: Package, Match: "p", Severity: "high", Title: "t",
			Versions: []string{"^1.2.3"}}},
		{"unparseable range bound", Entry{ID: "b", Kind: Package, Match: "p", Severity: "high", Title: "t",
			Ranges: []Range{{Introduced: "latest"}}}},
		{"empty range", Entry{ID: "c", Kind: Package, Match: "p", Severity: "high", Title: "t",
			Ranges: []Range{{Introduced: "2.0.0", Fixed: "1.0.0"}}}},
		{"boundless range", Entry{ID: "d", Kind: Package, Match: "p", Severity: "high", Title: "t",
			Ranges: []Range{{}}}},
		{"unknown kind", Entry{ID: "e", Kind: "model-repo", Match: "p", Severity: "high", Title: "t"}},
		{"typo severity", Entry{ID: "f", Kind: Package, Match: "p", Severity: "criticl", Title: "t"}},
		{"no match value", Entry{ID: "g", Kind: Package, Severity: "high", Title: "t"}},
		{"no title", Entry{ID: "h", Kind: Package, Match: "p", Severity: "high"}},
		{"no id", Entry{Kind: Package, Match: "p", Severity: "high", Title: "t"}},
	}
	for _, c := range cases {
		if probs := (Feed{Entries: []Entry{c.entry}}).Validate(); len(probs) == 0 {
			t.Errorf("%s: accepted an entry that cannot do what it says", c.name)
		}
	}
}

func TestValidateCatchesDuplicateIDs(t *testing.T) {
	f := Feed{Entries: []Entry{
		{ID: "dup", Kind: Package, Match: "a", Severity: "high", Title: "t"},
		{ID: "dup", Kind: Package, Match: "b", Severity: "high", Title: "t"},
	}}
	if probs := f.Validate(); len(probs) == 0 {
		t.Fatal("two entries sharing an id were accepted, so a report could not cite either one")
	}
}

func TestValidateAcceptsGoodEntries(t *testing.T) {
	f := Feed{Entries: []Entry{
		{ID: "ok-1", Kind: Package, Match: "p", Severity: "critical", Title: "t"},
		{ID: "ok-2", Kind: Package, Match: "p2", Severity: "high", Title: "t",
			Versions: []string{"1.0.0", "v1.0.1"}},
		{ID: "ok-3", Kind: Package, Match: "p3", Severity: "medium", Title: "t",
			Ranges: []Range{{Introduced: "1.0.0", Fixed: "1.2.0"}, {Introduced: "2.0.0"}}},
		{ID: "ok-4", Kind: NodeName, Match: "n", Severity: "critical", Title: "t"},
		{ID: "ok-5", Kind: FileDigest, Match: "abc", Severity: "critical", Title: "t"},
	}}
	if probs := f.Validate(); len(probs) != 0 {
		t.Errorf("good entries were rejected: %v", probs)
	}
}

// The shipped list is checked here so a broken entry fails the build rather
// than a user's report. It reads the file directly because the default build
// embeds no feed at all, and a test that silently skipped would be worse than
// no test.
func TestShippedFeedValidates(t *testing.T) {
	b, err := os.ReadFile("data/feed.json")
	if err != nil {
		t.Fatalf("the shipped feed could not be read: %v", err)
	}
	var f Feed
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("the shipped feed is not readable: %v", err)
	}
	if len(f.Entries) == 0 {
		t.Fatal("the shipped feed has no entries, so this test would prove nothing")
	}
	for _, p := range f.Validate() {
		t.Errorf("shipped feed: %s", p.Error())
	}
}

// --- release / rule-file staleness --------------------------------------

// The constant and the shipped file must not drift. If they do, either the
// warning never fires or it fires forever.
func TestReleasedWithMatchesShippedFeed(t *testing.T) {
	b, err := os.ReadFile("data/feed.json")
	if err != nil {
		t.Fatalf("the shipped feed could not be read: %v", err)
	}
	var f Feed
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("the shipped feed is not readable: %v", err)
	}
	if f.Version != ReleasedWith {
		t.Fatalf("ReleasedWith is %q but data/feed.json is %q; bump the constant when you bump the feed",
			ReleasedWith, f.Version)
	}
}

// The case this was written for: a previous release's rule file, still signed,
// still valid, sitting beside a newer binary.
func TestBehindReleaseDetectsAStaleRuleFile(t *testing.T) {
	older := Feed{Version: "2026.09.14.1"}
	behind, have, want := older.BehindRelease()
	if !behind {
		t.Fatalf("a rule file older than the release was not noticed (have %s, want %s)", have, want)
	}

	same := Feed{Version: ReleasedWith}
	if behind, _, _ := same.BehindRelease(); behind {
		t.Error("the release's own rule file was reported as stale")
	}

	// --update-feed is expected to move ahead of the binary. That is the
	// normal state, not a problem.
	newer := Feed{Version: "2099.01.01.1"}
	if behind, _, _ := newer.BehindRelease(); behind {
		t.Error("a rule file newer than the release was reported as stale")
	}

	// Nothing to compare: say nothing rather than guess.
	for _, v := range []string{"", "empty", "not-a-version"} {
		if behind, _, _ := (Feed{Version: v}).BehindRelease(); behind {
			t.Errorf("an unversioned feed (%q) was reported as stale", v)
		}
	}
}
