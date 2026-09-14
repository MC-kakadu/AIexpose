package control

import (
	"strings"
	"testing"

	"github.com/MC-kakadu/AIexpose/internal/model"
	"github.com/MC-kakadu/AIexpose/internal/supply"
)

func report(fs ...model.Finding) *model.Report {
	r := &model.Report{}
	for _, f := range fs {
		r.Add(f)
	}
	return r
}

func find(cov []model.ControlCoverage, id string) model.ControlCoverage {
	for _, c := range cov {
		if strings.HasPrefix(c.Control.ID, id) {
			return c
		}
	}
	return model.ControlCoverage{}
}

func TestFindingsCarryControls(t *testing.T) {
	r := report(model.Finding{ID: "SEC-002", Severity: model.Medium})
	Annotate(r)

	got := r.Findings[0].Controls
	if len(got) == 0 {
		t.Fatal("a credential finding carries no control references")
	}
	var frameworks []string
	for _, c := range got {
		frameworks = append(frameworks, c.Framework)
		if c.ID == "" || c.Title == "" || c.URL == "" {
			t.Errorf("incomplete control reference: %+v", c)
		}
	}
	for _, want := range []string{OWASP, ATLAS, ATTACK} {
		if !strings.Contains(strings.Join(frameworks, "|"), want) {
			t.Errorf("no %s reference on a plaintext-credential finding", want)
		}
	}
}

// The mapping table is shared by every finding with the same ID. Appending to
// it in place would leak one scan's refinements into the next finding.
func TestMappingTableIsNotMutated(t *testing.T) {
	before := len(byFinding["EXP-001"])

	r := report(model.Finding{ID: "EXP-001", Title: "Qdrant is bound to all interfaces", Severity: model.High})
	Annotate(r)
	r2 := report(model.Finding{ID: "EXP-001", Title: "Ollama is bound to all interfaces", Severity: model.High})
	Annotate(r2)

	if after := len(byFinding["EXP-001"]); after != before {
		t.Fatalf("the shared mapping grew from %d to %d entries", before, after)
	}
	if has(r2.Findings[0].Controls, "LLM08:2025") {
		t.Error("an Ollama finding picked up the vector-store control from an earlier scan")
	}
}

func TestExposedVectorStoreAddsTheEmbeddingRisk(t *testing.T) {
	r := report(model.Finding{ID: "EXP-001", Title: "Qdrant is bound to all interfaces", Severity: model.High})
	Annotate(r)
	if !has(r.Findings[0].Controls, "LLM08:2025") {
		t.Error("an exposed vector database is not mapped to the embedding risk")
	}
	if c := find(r.Coverage, "LLM08"); len(c.Findings) != 1 {
		t.Errorf("LLM08 coverage shows %v, want the EXP-001 finding", c.Findings)
	}
}

// A passing check is not evidence of a risk. Counting Info findings as
// coverage hits would turn "we looked and it was fine" into a red row.
func TestPassingChecksAreNotEvidence(t *testing.T) {
	r := report(
		model.Finding{ID: "SEC-000", Title: "No plaintext API keys found", Severity: model.Info},
		model.Finding{ID: "EXP-000", Title: "Ollama is bound to loopback only", Severity: model.Info},
	)
	Annotate(r)

	c := find(r.Coverage, "LLM02")
	if len(c.Findings) != 0 {
		t.Errorf("LLM02 lists %v as evidence, but both checks passed", c.Findings)
	}
	if c.Scope != model.ScopeChecked {
		t.Errorf("LLM02 scope = %q, want %q", c.Scope, model.ScopeChecked)
	}
}

// The credibility of the whole section rests on this: a risk the scanner
// cannot examine must never be reported as one it examined and cleared.
func TestEveryControlIsCoveredAndScoped(t *testing.T) {
	r := report()
	Annotate(r)

	if len(r.Coverage) != 10 {
		t.Fatalf("coverage has %d rows, want all 10 OWASP LLM entries", len(r.Coverage))
	}
	seen := map[string]bool{}
	for _, c := range r.Coverage {
		if seen[c.Control.ID] {
			t.Errorf("%s appears twice", c.Control.ID)
		}
		seen[c.Control.ID] = true

		switch c.Scope {
		case model.ScopeChecked, model.ScopePartial, model.ScopeNotChecked:
		default:
			t.Errorf("%s has scope %q, which is not one of the three states", c.Control.ID, c.Scope)
		}
		if strings.TrimSpace(c.Note) == "" {
			t.Errorf("%s has no note, so a reader cannot tell what was examined", c.Control.ID)
		}
		if c.Scope != model.ScopeChecked && len(c.Note) < 80 {
			t.Errorf("%s is not fully checked but its note is too short to explain why: %q", c.Control.ID, c.Note)
		}
	}
	for _, want := range []string{"LLM05:2025", "LLM09:2025"} {
		if find(r.Coverage, want[:6]).Scope != model.ScopeNotChecked {
			t.Errorf("%s should be reported as outside what a local scan can see", want)
		}
	}
}

func TestSeverityIsTheWorstOfTheEvidence(t *testing.T) {
	r := report(
		model.Finding{ID: "SUP-020", Severity: model.Medium},
		model.Finding{ID: "SUP-030", Severity: model.Critical},
		model.Finding{ID: "SUP-011", Severity: model.High},
	)
	Annotate(r)

	c := find(r.Coverage, "LLM03")
	if c.SevLabel != "CRITICAL" {
		t.Errorf("LLM03 severity = %q, want CRITICAL", c.SevLabel)
	}
	if len(c.Findings) != 3 {
		t.Errorf("LLM03 lists %v, want all three findings", c.Findings)
	}
}

func has(cs []model.Control, id string) bool {
	for _, c := range cs {
		if c.ID == id {
			return true
		}
	}
	return false
}

// --- inventory ----------------------------------------------------------

// Several MCP servers are configured in one file, so they share a path. A
// finding about one of them must not mark the others.
func TestFlagsOnlyTheComponentTheFindingNames(t *testing.T) {
	inv := supply.Inventory{Artifacts: []supply.Artifact{
		{Kind: "mcp-server", ID: "mcp-server:postmark@.claude.json", Name: "postmark",
			Path: "/home/u/.claude.json", Digest: strings.Repeat("a", 64),
			Detail: map[string]string{"package": "postmark-mcp", "package_version": "1.0.16"}},
		{Kind: "mcp-server", ID: "mcp-server:filesys@.claude.json", Name: "filesys",
			Path: "/home/u/.claude.json", Digest: strings.Repeat("b", 64),
			Detail: map[string]string{"package": "@scope/fs"}},
		{Kind: "mcp-server", ID: "mcp-server:notes@.claude.json", Name: "notes",
			Path: "/home/u/.claude.json", Digest: strings.Repeat("c", 64)},
	}}
	r := report(model.Finding{
		ID: "SUP-030", Severity: model.Critical,
		Detail:    "Path: /home/u/.claude.json",
		Artifacts: []string{"mcp-server:postmark@.claude.json"},
	})
	Annotate(r)
	Inventory(r, inv)

	got := map[string]string{}
	for _, c := range r.Components {
		got[c.Name] = c.Flag
	}
	if got["postmark"] != "CRITICAL" {
		t.Errorf("postmark flag = %q, want CRITICAL", got["postmark"])
	}
	for _, name := range []string{"filesys", "notes"} {
		if got[name] != "" {
			t.Errorf("%s was flagged %q because it shares a config file with postmark", name, got[name])
		}
	}
}

func TestInventoryDescribesEachKind(t *testing.T) {
	inv := supply.Inventory{Artifacts: []supply.Artifact{
		{Kind: "ollama-model", ID: "ollama-model:registry.ollama.ai/library/llama3:8b",
			Name: "llama3:8b", Digest: strings.Repeat("d", 64)},
		{Kind: "comfy-node", ID: "comfy-node:x", Name: "x", Digest: strings.Repeat("e", 64),
			Detail: map[string]string{"origin": "https://github.com/a/x.git"}},
		{Kind: "mcp-server", ID: "mcp-server:y", Name: "y",
			Detail: map[string]string{"package": "y-mcp"}},
	}}
	r := report()
	Inventory(r, inv)

	by := map[string]model.Component{}
	for _, c := range r.Components {
		by[c.Name] = c
	}
	if c := by["llama3:8b"]; c.Source != "registry.ollama.ai" || c.Version != "8b" {
		t.Errorf("model row = %+v, want the registry as source and 8b as version", c)
	}
	if c := by["x"]; c.Source != "https://github.com/a/x.git" {
		t.Errorf("node row source = %q, want the git origin", c.Source)
	}
	if c := by["y"]; c.Version != "unpinned" {
		t.Errorf("an MCP server with no pinned version shows %q, want \"unpinned\"", c.Version)
	}
	for _, c := range r.Components {
		if c.Digest != "" && len(c.Digest) != 12 {
			t.Errorf("%s digest is %d chars, want 12", c.Name, len(c.Digest))
		}
	}
}
