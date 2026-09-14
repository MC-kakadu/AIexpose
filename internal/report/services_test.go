package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/MC-kakadu/AIexpose/internal/model"
)

// An empty service list used to remove the whole section from the page. The
// terminal said "No known AI services are listening on this machine"; the page
// said nothing at all, so a reader could not tell whether the check had run.
// Silence is the one thing a report of this kind must never use for a result.
func TestEmptyServiceListStillSaysSo(t *testing.T) {
	r := &model.Report{Tool: "aiexpose", Version: "test", Host: "h"}
	r.Finalize()

	var buf bytes.Buffer
	if err := HTML(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Discovered services") {
		t.Fatal("the services section vanished when nothing was listening")
	}
	if !strings.Contains(out, "No AI service was listening") {
		t.Error("the page does not state that nothing was found")
	}
}

// And when the scan could not see everything, the page says which.
func TestServiceScopeCaveatIsRendered(t *testing.T) {
	r := &model.Report{Tool: "aiexpose", Version: "test", Host: "h"}
	r.ServiceScopeNote = "This scan ran without root, so sockets owned by other users were not visible."
	r.Finalize()

	var buf bytes.Buffer
	if err := HTML(&buf, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "without root") {
		t.Error("the scope caveat is missing from the page")
	}
}

// A detail written with blank lines between sentences rendered an empty
// paragraph, which shows up as a stray gap in the page.
func TestBlankLinesInADetailDoNotBecomeEmptyParagraphs(t *testing.T) {
	r := &model.Report{Tool: "aiexpose", Version: "test", Host: "h"}
	r.Add(model.Finding{
		ID: "SEC-002", Title: "keys", Severity: model.Medium,
		Detail: "First sentence.\n\nSecond sentence.\n\n\nThird.",
	})
	r.Finalize()

	var buf bytes.Buffer
	if err := HTML(&buf, r); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(buf.String(), "<p></p>"); n != 0 {
		t.Errorf("%d empty paragraph(s) rendered", n)
	}
	for _, want := range []string{"First sentence.", "Second sentence.", "Third."} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("dropping blank lines also dropped %q", want)
		}
	}
}
