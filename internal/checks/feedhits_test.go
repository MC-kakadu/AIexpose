package checks

import (
	"strings"
	"testing"
	"time"

	"github.com/MC-kakadu/AIexpose/internal/feed"
	"github.com/MC-kakadu/AIexpose/internal/model"
)

func findingsByID(r *model.Report, id string) []model.Finding {
	var out []model.Finding
	for _, f := range r.Findings {
		if f.ID == id {
			out = append(out, f)
		}
	}
	return out
}

func freshFeed(entries ...feed.Entry) feed.Feed {
	return feed.Feed{
		Version: "test", Updated: time.Now(), Origin: "test fixture", Entries: entries,
	}
}

// The case the version work exists for: a legitimate package that was briefly
// hijacked must produce a finding on the affected releases and silence on the
// clean ones.
func TestKnownBadReportsOnlyAffectedVersions(t *testing.T) {
	e := feed.Entry{
		ID: "AIX-T-1", Kind: feed.Package, Match: "ultralytics", Severity: "critical",
		Title:    "ultralytics shipped a cryptominer in four releases",
		Versions: []string{"8.3.41", "8.3.42", "8.3.45", "8.3.46"},
	}

	var bad model.Report
	reportFeedHits(&bad, freshFeed(e), []feed.Component{
		{ID: "c1", Name: "ultralytics", Package: "ultralytics", Version: "8.3.41", Path: "/p"},
	})
	hits := findingsByID(&bad, "SUP-030")
	if len(hits) != 1 {
		t.Fatalf("an affected release produced %d findings, want 1", len(hits))
	}
	if hits[0].Severity != model.Critical {
		t.Errorf("affected release reported at %v, want CRITICAL", hits[0].Severity)
	}

	var clean model.Report
	reportFeedHits(&clean, freshFeed(e), []feed.Component{
		{ID: "c1", Name: "ultralytics", Package: "ultralytics", Version: "8.3.40", Path: "/p"},
	})
	if got := findingsByID(&clean, "SUP-030"); len(got) != 0 {
		t.Fatalf("a clean release was accused: %s", got[0].Title)
	}
	// And the clean run must still say the check ran.
	if got := findingsByID(&clean, "SUP-032"); len(got) != 1 {
		t.Error("a clean result did not record that the list was checked")
	}
}

// An unresolvable version must not be filed as a confirmed match, must not be
// dropped, and must not be filed under "nothing matched".
func TestUnresolvedVersionIsReportedAsOpenNotAsMalware(t *testing.T) {
	e := feed.Entry{
		ID: "AIX-T-2", Kind: feed.Package, Match: "litellm", Severity: "critical",
		Title: "litellm releases were hijacked", Versions: []string{"1.82.7", "1.82.8"},
	}
	var r model.Report
	reportFeedHits(&r, freshFeed(e), []feed.Component{
		{ID: "c1", Name: "litellm", Package: "litellm", Version: "latest", Path: "/p"},
	})

	if got := findingsByID(&r, "SUP-030"); len(got) != 0 {
		t.Errorf("an uncompared version was reported as a confirmed match: %s", got[0].Title)
	}
	open := findingsByID(&r, "SUP-034")
	if len(open) != 1 {
		t.Fatalf("an uncompared version produced %d open findings, want 1", len(open))
	}
	if open[0].Severity == model.Critical {
		t.Error("an open question was reported at the entry's own critical severity")
	}
	if !strings.Contains(open[0].Detail, "not a finding that the component is malicious") {
		t.Error("the finding does not say plainly that nothing was established")
	}
	if got := findingsByID(&r, "SUP-032"); len(got) != 0 {
		t.Error("an unresolved hit was followed by 'nothing appears on the known-bad list'")
	}
}

// A list whose entries cannot do what they say covers less than it appears to,
// and the report has to admit that rather than quoting a clean result from it.
func TestBrokenFeedEntriesAreDeclared(t *testing.T) {
	var r model.Report
	reportFeedHits(&r, freshFeed(
		feed.Entry{ID: "AIX-T-3", Kind: feed.NodeName, Match: "n", Severity: "critical",
			Title: "t", Versions: []string{"1.0.0"}},
	), nil)

	probs := findingsByID(&r, "SUP-033")
	if len(probs) != 1 {
		t.Fatalf("a list with an unusable entry produced %d warnings, want 1", len(probs))
	}
	if !probs[0].Advisory {
		t.Error("a gap in the list's own coverage did not mark the report incomplete")
	}
	if len(probs[0].Evidence) == 0 {
		t.Error("the warning does not say which entry is wrong")
	}
}

func TestSoundFeedRaisesNoEntryWarning(t *testing.T) {
	var r model.Report
	reportFeedHits(&r, freshFeed(
		feed.Entry{ID: "AIX-T-4", Kind: feed.Package, Match: "p", Severity: "critical", Title: "t",
			Ranges: []feed.Range{{Introduced: "1.0.0", Fixed: "1.1.0"}}},
	), nil)
	if got := findingsByID(&r, "SUP-033"); len(got) != 0 {
		t.Errorf("a sound list was reported as broken: %v", got[0].Evidence)
	}
}

// An unpinned launch spec resolves to whatever the registry serves, so it is a
// real finding even though no affected version is on disk -- and the reason has
// to say which it is.
func TestUnpinnedPackageIsReportedWithItsReason(t *testing.T) {
	var r model.Report
	reportFeedHits(&r, freshFeed(
		feed.Entry{ID: "AIX-T-5", Kind: feed.Package, Match: "ultralytics", Severity: "critical",
			Title: "t", Versions: []string{"8.3.41"}},
	), []feed.Component{{ID: "c1", Name: "ultralytics", Package: "ultralytics", Path: "/p"}})

	hits := findingsByID(&r, "SUP-030")
	if len(hits) != 1 {
		t.Fatalf("an unpinned install of a listed package produced %d findings, want 1", len(hits))
	}
	if !strings.Contains(hits[0].Detail, "unpinned") {
		t.Error("the finding does not explain that the spec is unpinned")
	}
}
