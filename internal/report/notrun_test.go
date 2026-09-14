package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/MC-kakadu/AIexpose/internal/model"
)

func notRunReport() *model.Report {
	r := &model.Report{Tool: "aiexpose", Version: "test"}
	r.Add(model.Finding{
		ID: "SEC-000", Title: "No plaintext API keys found in the places checked",
		Severity: model.Info, Detail: "Shell profiles were checked.",
	})
	r.Add(model.Finding{
		ID: "SEC-004", Title: "Your document folders were not searched for API keys",
		Severity: model.Info, NotRun: true, Detail: "Desktop and Documents were not read.",
		Command: "aiexpose --scan-docs",
	})
	r.Finalize()
	return r
}

// The HTML report has separated not-run checks since v0.17.1, when a real
// report listed "shell history was not searched" among the passes. The
// terminal kept mixing them, so the same false comfort survived for everyone
// running this over SSH or in CI.
func TestTerminalSeparatesChecksThatDidNotRun(t *testing.T) {
	var buf bytes.Buffer
	Terminal(&buf, notRunReport(), false, true)
	out := buf.String()

	head := strings.Index(out, "Checks that did not run")
	if head < 0 {
		t.Fatal("verbose output has no section for checks that did not run")
	}
	passed := strings.Index(out, "No plaintext API keys found")
	skipped := strings.Index(out, "Your document folders were not searched")
	if skipped < 0 {
		t.Fatal("the not-run check is missing entirely")
	}
	if passed > head {
		t.Error("a check that passed was printed inside the did-not-run section")
	}
	if skipped < head {
		t.Error("a check that did not run was printed above the section heading, among the passes")
	}
	if !strings.Contains(out, "NOT RUN") {
		t.Error("the not-run check is not labelled NOT RUN")
	}
}

// Without --verbose the informational findings are hidden, but the fact that
// something was skipped must survive: that is the difference between a clean
// result and a complete one.
func TestTerminalSaysSomethingWasSkippedEvenWhenQuiet(t *testing.T) {
	var buf bytes.Buffer
	Terminal(&buf, notRunReport(), false, false)
	out := buf.String()

	if strings.Contains(out, "NOT RUN") {
		t.Error("the not-run detail was printed without --verbose")
	}
	if !strings.Contains(out, "did not run") {
		t.Errorf("a quiet run hides that checks were skipped:\n%s", out)
	}
	if !strings.Contains(out, "not a complete result") {
		t.Error("the quiet summary does not say the result is incomplete")
	}
}

// And a report with nothing skipped must not grow an empty section.
func TestTerminalOmitsTheSectionWhenEverythingRan(t *testing.T) {
	r := &model.Report{Tool: "aiexpose", Version: "test"}
	r.Add(model.Finding{ID: "SEC-000", Title: "No plaintext API keys found", Severity: model.Info})
	r.Finalize()

	var buf bytes.Buffer
	Terminal(&buf, r, false, true)
	if strings.Contains(buf.String(), "did not run") {
		t.Error("an empty did-not-run section was printed")
	}
}
