package report

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/MC-kakadu/AIexpose/internal/model"
)

func renderHTML(t *testing.T, f model.Finding) string {
	t.Helper()
	r := &model.Report{Host: "test"}
	r.Add(f)
	r.Finalize()
	var buf bytes.Buffer
	if err := HTML(&buf, r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// A finding with a long evidence list has to fold away, and folding must never
// mean losing anything: the terminal shows a sample, the report shows all of it.
func TestEvidenceFoldsWhenLong(t *testing.T) {
	var ev []string
	for i := 0; i < 14; i++ {
		ev = append(ev, fmt.Sprintf("C:\\models\\weights_%d.bin", i))
	}
	out := renderHTML(t, model.Finding{
		Severity: model.Low, Title: "many files", Detail: "d", Evidence: ev,
	})

	if !strings.Contains(out, `<details class="ev">`) {
		t.Error("a 14-item list must be behind a disclosure")
	}
	if strings.Contains(out, `<details class="ev" open>`) {
		t.Error("the disclosure must start closed")
	}
	if !strings.Contains(out, "Show all 14 items") {
		t.Error("the summary must say how many there are")
	}
	for _, e := range ev {
		if !strings.Contains(out, strings.ReplaceAll(e, `\`, `\`)) {
			t.Fatalf("evidence item missing from the page: %s", e)
		}
	}
	if strings.Contains(out, "... and") {
		t.Error("the page must not truncate; that is the terminal's job")
	}
}

// A short list is not worth a click.
func TestShortEvidenceIsShownDirectly(t *testing.T) {
	out := renderHTML(t, model.Finding{
		Severity: model.Low, Title: "few files", Detail: "d",
		Evidence: []string{"a.bin", "b.bin", "c.bin"},
	})
	if strings.Contains(out, "<details") {
		t.Error("three items should be shown without a disclosure")
	}
	for _, e := range []string{"a.bin", "b.bin", "c.bin"} {
		if !strings.Contains(out, e) {
			t.Errorf("missing %s", e)
		}
	}
}

func TestNoEvidenceRendersNothing(t *testing.T) {
	out := renderHTML(t, model.Finding{Severity: model.Low, Title: "plain", Detail: "d"})
	// The class is always defined in the stylesheet; what must not appear is an
	// element using it.
	if strings.Contains(out, `<div class="evlist">`) || strings.Contains(out, "<details") {
		t.Error("a finding with no evidence must not render an empty list")
	}
}

// Evidence attached to an informational finding is shown too; it lives in a
// different section of the page and used to be dropped.
func TestInfoFindingsShowEvidence(t *testing.T) {
	out := renderHTML(t, model.Finding{
		Severity: model.Info, Title: "passed", Detail: "d",
		Evidence: []string{"detail-one", "detail-two"},
	})
	if !strings.Contains(out, "detail-one") {
		t.Error("informational findings must render their evidence as well")
	}
}

// Paths and excerpts come from the filesystem and from third-party source, so
// they must never be able to inject markup into the report.
func TestEvidenceIsEscaped(t *testing.T) {
	out := renderHTML(t, model.Finding{
		Severity: model.High, Title: "x", Detail: "d",
		Evidence: []string{`<script>alert(1)</script>`},
	})
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Fatal("evidence was not escaped")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("evidence should appear, escaped")
	}
}

// The four coverage states must render differently. A report that showed "not
// checked" the same way as "no evidence found" would be lying by layout.
func TestCoverageBadgesAreDistinct(t *testing.T) {
	cases := []struct {
		name string
		cov  model.ControlCoverage
		want string
	}{
		{"evidence", model.ControlCoverage{Scope: model.ScopeChecked,
			Findings: []string{"SUP-030"}, SevLabel: "CRITICAL"}, "critical"},
		{"clear", model.ControlCoverage{Scope: model.ScopeChecked}, "no evidence found"},
		{"partial", model.ControlCoverage{Scope: model.ScopePartial}, "partly checked"},
		{"blind", model.ControlCoverage{Scope: model.ScopeNotChecked}, "not checked"},
	}
	seen := map[string]bool{}
	for _, c := range cases {
		got := string(covBadge(c.cov))
		if !strings.Contains(got, c.want) {
			t.Errorf("%s badge = %q, want it to contain %q", c.name, got, c.want)
		}
		if seen[got] {
			t.Errorf("%s renders identically to an earlier state: %q", c.name, got)
		}
		seen[got] = true
	}
}

// A "not checked" row that never says so is worse than no row at all.
func TestReportRendersCoverageAndAttestation(t *testing.T) {
	r := &model.Report{
		Tool: "aiexpose", Version: "9.9.9", Host: "box", OS: "linux", Arch: "amd64",
		Started: time.Now(), Duration: "10ms",
		Attest: model.Attestation{
			Tool: "aiexpose", Version: "9.9.9", Profile: "default",
			SelfDigest: strings.Repeat("a", 64), RuleCounts: "11 code indicator(s)",
		},
		Coverage: []model.ControlCoverage{
			{Control: model.Control{ID: "LLM05:2025", Title: "Improper Output Handling",
				URL: "https://genai.owasp.org/llm-top-10/"},
				Scope: model.ScopeNotChecked, Note: "a property of the application's code"},
		},
		Components: []model.Component{
			{Kind: "MCP server", Name: "postmark", Version: "1.0.16",
				Source: "postmark-mcp", Digest: "abc123abc123", Flag: "CRITICAL"},
		},
	}
	var buf bytes.Buffer
	if err := HTML(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"Risk coverage", "LLM05:2025", "not checked",
		"How this report was produced", strings.Repeat("a", 64),
		"AI components installed", "postmark", "abc123abc123", "flagged",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not contain %q", want)
		}
	}
}

// A check that did not run must not appear under "checks that passed".
func TestNotRunChecksAreSeparated(t *testing.T) {
	r := &model.Report{Tool: "aiexpose", Version: "9.9.9", Host: "box", Started: time.Now()}
	r.Add(model.Finding{ID: "FW-000", Title: "Host firewall is enabled", Severity: model.Info})
	r.Add(model.Finding{ID: "SUP-053", Title: "The malware hash index had nothing to check",
		Severity: model.Info, NotRun: true, Detail: "not a pass"})
	r.Finalize()

	var buf bytes.Buffer
	if err := HTML(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	passed := strings.Index(out, "Checks that passed")
	notrun := strings.Index(out, "Checks that did not run")
	if passed < 0 || notrun < 0 {
		t.Fatalf("sections missing: passed=%d notRun=%d", passed, notrun)
	}
	// The not-run finding has to sit in the second section, not the first.
	idx := strings.Index(out, "nothing to check")
	if idx < notrun {
		t.Error("a not-run check was rendered under the checks that passed")
	}
	if strings.Index(out, "Host firewall is enabled") > notrun {
		t.Error("a check that passed was rendered under the ones that did not run")
	}
}

// The report has to name the executable the reader actually ran, or the
// verification command it prints does not work.
func TestVerifyCommandNamesTheRealExecutable(t *testing.T) {
	r := &model.Report{Tool: "aiexpose", OS: "windows",
		Attest: model.Attestation{ExePath: `C:\dev\aiexpose_0.17.0_windows_amd64.exe`}}
	if got, want := verifyCmd(r), `.\aiexpose_0.17.0_windows_amd64.exe --verify SHA256SUMS`; got != want {
		t.Errorf("verifyCmd = %q, want %q", got, want)
	}
	u := &model.Report{Tool: "aiexpose", OS: "linux",
		Attest: model.Attestation{ExePath: "/usr/local/bin/aiexpose"}}
	if got, want := verifyCmd(u), "./aiexpose --verify SHA256SUMS"; got != want {
		t.Errorf("verifyCmd = %q, want %q", got, want)
	}
	if got := verifyCmd(&model.Report{Tool: "aiexpose"}); got != "aiexpose --verify SHA256SUMS" {
		t.Errorf("with no path known, verifyCmd = %q", got)
	}
}
