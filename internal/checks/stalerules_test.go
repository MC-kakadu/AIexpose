package checks

import (
	"strings"
	"testing"

	"github.com/MC-kakadu/AIexpose/internal/feed"
	"github.com/MC-kakadu/AIexpose/internal/model"
)

// The regression this was written for: a previous release's rule file, still
// validly signed, loaded in preference to nothing, and reported as though it
// were the current list.
func TestStaleRuleFileIsReported(t *testing.T) {
	var r model.Report
	staleRuleFile(&r, feed.Feed{Version: "2026.09.14.1", Origin: "shipped beside the executable"})

	got := findingsByID(&r, "RULE-002")
	if len(got) != 1 {
		t.Fatalf("a rule file older than the release produced %d findings, want 1", len(got))
	}
	if !got[0].Advisory {
		t.Error("an incomplete rule set did not mark the report incomplete")
	}
	if !strings.Contains(got[0].Detail, "2026.09.14.1") || !strings.Contains(got[0].Detail, feed.ReleasedWith) {
		t.Error("the finding does not name both versions, so the reader cannot tell how far behind they are")
	}
	if got[0].Command == "" {
		t.Error("the finding does not say how to fix it")
	}
}

func TestCurrentAndNewerRuleFilesAreNotReported(t *testing.T) {
	for _, v := range []string{feed.ReleasedWith, "2099.01.01.1", "", "empty"} {
		var r model.Report
		staleRuleFile(&r, feed.Feed{Version: v, Origin: "test"})
		if got := findingsByID(&r, "RULE-002"); len(got) != 0 {
			t.Errorf("rule version %q was reported as stale: %s", v, got[0].Title)
		}
	}
}
