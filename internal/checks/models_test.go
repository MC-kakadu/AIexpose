package checks

import (
	"testing"

	"github.com/MC-kakadu/AIexpose/internal/model"
)

// A checkpoint PyTorch fetched from its own hub and a .ckpt someone downloaded
// from a forum are the same file format and very different propositions. If
// both are reported at one severity, a machine with nothing but stock
// torchvision weights loses a grade for it, and the finding that matters is
// buried among fifteen that do not.
func TestPickleSeverityDependsOnProvenance(t *testing.T) {
	cached := map[string]int64{"/home/u/.cache/torch/hub/vgg16.pth": 100}
	added := map[string]int64{"/home/u/ComfyUI/models/x.ckpt": 100}

	only := func(chosen, managed map[string]int64) *model.Report {
		r := &model.Report{}
		reportPickles(r, chosen, managed, len(chosen)+len(managed), 0)
		r.Finalize()
		return r
	}

	cachedOnly := only(nil, cached)
	if got := severityOf(t, cachedOnly, "MDL-002"); got != model.Low {
		t.Errorf("framework cache severity = %v, want Low", got)
	}
	if len(findingsWithID(cachedOnly, "MDL-001")) != 0 {
		t.Error("a cache-only machine must not get the user-added finding")
	}

	addedOnly := only(added, nil)
	if got := severityOf(t, addedOnly, "MDL-001"); got != model.Medium {
		t.Errorf("user-added severity = %v, want Medium", got)
	}

	both := only(added, cached)
	if len(findingsWithID(both, "MDL-001")) != 1 || len(findingsWithID(both, "MDL-002")) != 1 {
		t.Errorf("both kinds must be reported separately: %+v", both.Findings)
	}
	// The one the user can act on has to sort above the one they cannot.
	if both.Findings[0].ID != "MDL-001" {
		t.Errorf("findings[0] = %s, want the actionable MDL-001 first", both.Findings[0].ID)
	}
}

func TestNoPicklesReportsNothingToFix(t *testing.T) {
	r := &model.Report{}
	reportPickles(r, nil, nil, 0, 5)
	r.Finalize()
	if r.Score != 100 {
		t.Errorf("safe formats only must not cost anything: score %d", r.Score)
	}
	if len(findingsWithID(r, "MDL-000")) != 1 {
		t.Error("a machine with only safe formats should be told so")
	}
}

func findingsWithID(r *model.Report, id string) []model.Finding {
	var out []model.Finding
	for _, f := range r.Findings {
		if f.ID == id {
			out = append(out, f)
		}
	}
	return out
}

func severityOf(t *testing.T, r *model.Report, id string) model.Severity {
	t.Helper()
	fs := findingsWithID(r, id)
	if len(fs) != 1 {
		t.Fatalf("expected exactly one %s finding, got %d", id, len(fs))
	}
	return fs[0].Severity
}
