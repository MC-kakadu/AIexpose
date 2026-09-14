// Package control maps what this scanner found to the published frameworks a
// reader already has to answer to.
//
// The value is not the labels. It is that a finding stops being one tool's
// opinion and becomes an entry someone can put in a risk register, paste into a
// vendor security questionnaire, or hand to an auditor who has never heard of
// this program.
//
// The harder half is the coverage map. A scanner that lists only what it found
// invites the reader to assume it looked everywhere, and for a local scanner
// that assumption is badly wrong: half of the OWASP LLM Top 10 describes
// runtime behaviour of an application, and nothing on disk reveals it. Naming
// those gaps beside the findings is what makes the rest of the report
// trustworthy. It is also the honest answer to "are we covered?", which is the
// question the person reading this actually has.
package control

import (
	"sort"
	"strings"

	"github.com/MC-kakadu/AIexpose/internal/model"
	"github.com/MC-kakadu/AIexpose/internal/supply"
)

// Framework names, spelled once.
const (
	OWASP  = "OWASP LLM Top 10 (2025)"
	ATLAS  = "MITRE ATLAS"
	ATTACK = "MITRE ATT&CK"
)

// owasp returns one OWASP LLM Top 10 entry.
func owasp(id, title string) model.Control {
	return model.Control{Framework: OWASP, ID: id, Title: title, URL: "https://genai.owasp.org/llm-top-10/"}
}

func atlas(id, title string) model.Control {
	return model.Control{Framework: ATLAS, ID: id, Title: title,
		URL: "https://atlas.mitre.org/techniques/" + id}
}

func attack(id, title string) model.Control {
	return model.Control{Framework: ATTACK, ID: id, Title: title,
		URL: "https://attack.mitre.org/techniques/" + strings.Replace(id, ".", "/", 1) + "/"}
}

// The OWASP LLM Top 10, 2025 release. Held as variables so the coverage table
// and the per-finding mapping cannot drift apart.
var (
	llm01 = owasp("LLM01:2025", "Prompt Injection")
	llm02 = owasp("LLM02:2025", "Sensitive Information Disclosure")
	llm03 = owasp("LLM03:2025", "Supply Chain")
	llm04 = owasp("LLM04:2025", "Data and Model Poisoning")
	llm05 = owasp("LLM05:2025", "Improper Output Handling")
	llm06 = owasp("LLM06:2025", "Excessive Agency")
	llm07 = owasp("LLM07:2025", "System Prompt Leakage")
	llm08 = owasp("LLM08:2025", "Vector and Embedding Weaknesses")
	llm09 = owasp("LLM09:2025", "Misinformation")
	llm10 = owasp("LLM10:2025", "Unbounded Consumption")
)

// byFinding maps a finding ID to the controls it is evidence for.
//
// The mapping is deliberately narrow. A finding listed against five frameworks
// looks thorough and means nothing; each entry here is one a reader could
// defend if challenged.
var byFinding = map[string][]model.Control{
	// Exposure: a service someone else can reach. EXP-000 is the pass, and it
	// carries the same labels so a reader can see which risk was cleared.
	"EXP-000": {llm02, llm10},
	"EXP-001": {llm02, llm10, atlas("AML.T0049", "Exploit Public-Facing Application"),
		atlas("AML.T0034", "Cost Harvesting")},
	"EXP-002": {llm02, llm10, atlas("AML.T0049", "Exploit Public-Facing Application"),
		atlas("AML.T0034", "Cost Harvesting")},
	// Unauthenticated on loopback is a disclosure risk, not a capacity one: a
	// stranger cannot reach it, so nobody else can spend your GPU on it.
	"EXP-003": {llm02},

	// Configuration that causes exposure.
	"CFG-001": {llm02, llm10, atlas("AML.T0049", "Exploit Public-Facing Application")},
	"CFG-002": {llm02, atlas("AML.T0049", "Exploit Public-Facing Application")},
	"CFG-003": {llm02, llm10, atlas("AML.T0049", "Exploit Public-Facing Application")},

	// Router and firewall: the same exposure, one hop further out.
	"NAT-000": {llm10},
	"NAT-001": {llm02, llm10, atlas("AML.T0049", "Exploit Public-Facing Application"),
		atlas("AML.T0034", "Cost Harvesting")},
	"NAT-002": {llm10, atlas("AML.T0049", "Exploit Public-Facing Application")},
	"FW-000":  {llm10},
	"FW-001":  {llm10, atlas("AML.T0049", "Exploit Public-Facing Application")},
	"FW-002":  {llm10, atlas("AML.T0049", "Exploit Public-Facing Application")},

	// Credentials sitting in plaintext.
	"SEC-000": {llm02},
	"SEC-001": {llm02, atlas("AML.T0055", "Unsecured Credentials"),
		attack("T1552.003", "Unsecured Credentials: Shell History")},
	"SEC-002": {llm02, atlas("AML.T0055", "Unsecured Credentials"),
		attack("T1552.001", "Unsecured Credentials: Credentials In Files")},

	// Model file formats that execute code when loaded.
	"MDL-000": {llm04},
	"MDL-001": {llm04, atlas("AML.T0018", "Backdoor ML Model")},
	"MDL-002": {llm04, atlas("AML.T0018", "Backdoor ML Model")},

	// Supply chain: what is installed, what changed, what is known bad.
	"SUP-000": {llm03},
	"SUP-001": {llm02, llm03, attack("T1567.004", "Exfiltration Over Web Service: Exfiltration Over Webhook"),
		attack("T1555.003", "Credentials from Password Stores: Credentials from Web Browsers")},
	"SUP-002": {llm03},
	"SUP-010": {llm03, atlas("AML.T0048", "Compromise ML Software Dependencies")},
	"SUP-011": {llm03, atlas("AML.T0048", "Compromise ML Software Dependencies")},
	"SUP-012": {llm03, atlas("AML.T0048", "Compromise ML Software Dependencies")},
	"SUP-013": {llm03},
	"SUP-020": {llm03, atlas("AML.T0048", "Compromise ML Software Dependencies")},
	"SUP-030": {llm03, atlas("AML.T0048", "Compromise ML Software Dependencies")},
	"SUP-031": {llm03},
	"SUP-032": {llm03},
	"SUP-040": {llm04, atlas("AML.T0018", "Backdoor ML Model")},
	"SUP-041": {llm03, llm04, atlas("AML.T0048", "Compromise ML Software Dependencies")},
	"SUP-050": {llm03, atlas("AML.T0048", "Compromise ML Software Dependencies")},
	"SUP-052": {llm03},
	"SUP-053": {llm03},
}

// vectorStores are the services whose exposure is specifically an embedding
// risk rather than a generic one. The finding ID is shared across every
// service, so the service name is what distinguishes them.
var vectorStores = []string{"Qdrant", "Chroma", "Weaviate", "Milvus"}

// Annotate fills in the control references on every finding and builds the
// coverage table. It runs after Finalize, because it reads the findings.
func Annotate(r *model.Report) {
	for i := range r.Findings {
		f := &r.Findings[i]
		c, ok := byFinding[f.ID]
		if !ok {
			continue
		}
		// Copy: the table is shared across every finding with this ID, and
		// appending to it in place would leak into the next scan's findings.
		out := make([]model.Control, len(c))
		copy(out, c)

		// An exposed vector database is the concrete form of the embedding
		// risk, and the finding ID alone cannot tell us that -- every exposed
		// service shares it. The service name in the headline can.
		if strings.HasPrefix(f.ID, "EXP-") && f.Severity != model.Info && namesVectorStore(f.Title) {
			out = append(out, llm08)
		}
		f.Controls = out
	}
	r.Coverage = coverage(r)
}

func namesVectorStore(title string) bool {
	for _, v := range vectorStores {
		if strings.Contains(title, v) {
			return true
		}
	}
	return false
}

// scopeNote is the static half of the coverage table: what this scanner looks
// at for each risk, and what it is blind to. It does not depend on results, so
// it reads the same on a clean machine and a compromised one.
var scopeNotes = []model.ControlCoverage{
	{Control: llm01, Scope: model.ScopePartial,
		Note: "Stored system prompts and Ollama Modelfile templates are read and inspected for instructions that exfiltrate data or reach for credentials, and a tampered template is detected without any threat data. " +
			"Injection that arrives at runtime -- in a user's message, a fetched page, a retrieved document -- happens inside the application and leaves nothing on disk. This scan cannot see it."},

	{Control: llm02, Scope: model.ScopeChecked,
		Note: "Plaintext API keys in shell profiles, .env files and (opt-in) shell history; services whose API answers without credentials; components carrying code that reads browser password stores or posts data to a webhook."},

	{Control: llm03, Scope: model.ScopeChecked,
		Note: "Every installed ComfyUI custom node, MCP server, agent skill and Ollama model is inventoried and fingerprinted, compared against the state you accepted, matched against a signed known-bad list, and -- when an index is built -- against a malware hash corpus. Unpinned package specs are flagged because they resolve to whatever the registry serves next."},

	{Control: llm04, Scope: model.ScopeChecked,
		Note: "Content-addressed model blobs are verified against their own names, so an edited model is detected with no threat data at all. Weights in pickle formats are reported because loading one executes code. Models from registries other than the official one are named."},

	{Control: llm05, Scope: model.ScopeNotChecked,
		Note: "Whether an application sanitises what the model returns before rendering, executing or querying with it is a property of that application's code. Nothing in a machine's configuration reveals it. Review the application, or test it."},

	{Control: llm06, Scope: model.ScopePartial,
		Note: "The inventory shows what each MCP server and agent skill is wired to reach, including which credential environment variables it is handed -- that is the ceiling on what an agent can do. " +
			"Whether that ceiling is higher than the job needs is a policy judgement. The CI gate (aiexpose ci) is where that judgement gets written down and enforced; the scan itself does not make it."},

	{Control: llm07, Scope: model.ScopePartial,
		Note: "Stored system prompts are read, so tampering with one is detected. Whether a running model discloses its prompt when asked is a runtime property this scan does not test."},

	{Control: llm08, Scope: model.ScopePartial,
		Note: "Qdrant, Chroma, Weaviate and Milvus are recognised, and their binding and authentication are checked -- an exposed vector store is the most common way embeddings leak. " +
			"Embedding inversion, cross-tenant retrieval and poisoned documents inside an index are not examined."},

	{Control: llm09, Scope: model.ScopeNotChecked,
		Note: "Whether a model's output is wrong, and whether anyone over-relies on it, is a property of the output and the process around it. A configuration scan has nothing to say about either."},

	{Control: llm10, Scope: model.ScopeChecked,
		Note: "Inference endpoints reachable from the network or forwarded from the internet, and endpoints that answer without credentials. This is the ShadowRay path: an exposed cluster dashboard turning into someone else's compute bill. Rate limiting inside the application is not examined."},
}

// coverage joins the static scope notes to what this particular scan found.
func coverage(r *model.Report) []model.ControlCoverage {
	hits := map[string][]string{}
	worst := map[string]model.Severity{}
	for _, f := range r.Findings {
		// An Info finding is a check that passed. Recording it as evidence
		// against a control would turn "we looked and it was fine" into a
		// mark in the risk column.
		if f.Severity == model.Info {
			continue
		}
		for _, c := range f.Controls {
			if c.Framework != OWASP {
				continue
			}
			if !contains(hits[c.ID], f.ID) {
				hits[c.ID] = append(hits[c.ID], f.ID)
			}
			if f.Severity > worst[c.ID] {
				worst[c.ID] = f.Severity
			}
		}
	}

	out := make([]model.ControlCoverage, 0, len(scopeNotes))
	for _, cc := range scopeNotes {
		ids := hits[cc.Control.ID]
		sort.Strings(ids)
		cc.Findings = ids
		if len(ids) > 0 {
			cc.Severity = worst[cc.Control.ID]
			cc.SevLabel = cc.Severity.String()
		}
		out = append(out, cc)
	}
	return out
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// Summary counts the coverage table for a one-line headline.
type Summary struct {
	Checked     int
	Partial     int
	NotChecked  int
	WithFinding int
}

// Summarise reduces the coverage table to counts.
func Summarise(cov []model.ControlCoverage) Summary {
	var s Summary
	for _, c := range cov {
		switch c.Scope {
		case model.ScopeChecked:
			s.Checked++
		case model.ScopePartial:
			s.Partial++
		default:
			s.NotChecked++
		}
		if len(c.Findings) > 0 {
			s.WithFinding++
		}
	}
	return s
}

// componentLabel names a component kind the way a person would say it.
func componentLabel(kind string) string {
	switch kind {
	case "comfy-node":
		return "ComfyUI node"
	case "mcp-server":
		return "MCP server"
	case "agent-skill":
		return "Agent skill"
	case "ollama-model":
		return "Ollama model"
	}
	return kind
}

// Inventory turns the supply-chain inventory into the report's component
// table, and marks the entries this report has a finding about.
//
// A summary line saying "6 components match the baseline" is a claim. The list
// is what lets a reader check it, and it is the half of an evidence report that
// outlives the findings: next quarter the findings will be different and the
// inventory is what someone compares against.
func Inventory(r *model.Report, inv supply.Inventory) {
	flagged := flaggedArtifacts(r)
	states, stateSev := componentStates(r)
	out := make([]model.Component, 0, len(inv.Artifacts))
	for _, a := range inv.Artifacts {
		c := model.Component{
			Kind: componentLabel(a.Kind), Name: a.Name, Path: a.Path,
			Version:  a.Detail["package_version"],
			Flag:     flagged[a.ID],
			State:    states[a.ID],
			StateSev: stateSev[a.ID],
		}
		if len(a.Digest) >= 12 {
			c.Digest = a.Digest[:12]
		}
		switch {
		case a.Kind == "ollama-model":
			c.Source = registryOf(a.ID)
			if c.Version == "" {
				if i := strings.LastIndex(a.Name, ":"); i > 0 {
					c.Version = a.Name[i+1:]
				}
			}
		case a.Detail["package"] != "":
			c.Source = a.Detail["package"]
			if c.Version == "" {
				c.Version = "unpinned"
			}
		case a.Detail["origin"] != "":
			c.Source = a.Detail["origin"]
			if c.Version == "" {
				c.Version = a.Detail["version"]
			}
		case a.Detail["publisher"] != "":
			c.Source = "publisher " + a.Detail["publisher"]
			if c.Version == "" {
				c.Version = a.Detail["version"]
			}
		case a.Detail["config"] != "":
			c.Source = a.Detail["config"]
		}
		out = append(out, c)
	}
	// Kind, then name, then path -- a total order. The same node name can
	// exist in two ComfyUI installs, and without the last key their rows would
	// swap between runs.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Path < out[j].Path
	})
	r.Components = out
}

// reviewOnly are findings that ask the reader to vouch for a component rather
// than warning them about it. A model you pulled an hour ago is unreviewed, not
// dangerous, and colouring its row like a malware hit is how a scanner teaches
// people to ignore red.
var reviewOnly = map[string]bool{"SUP-012": true, "SUP-013": true}

// componentStates records which components are waiting to be accepted, and at
// what severity the report rated that. The severity is carried through so the
// table and the finding cannot disagree about how much this matters.
func componentStates(r *model.Report) (map[string]string, map[string]string) {
	label := map[string]string{}
	sev := map[string]string{}
	for _, f := range r.Findings {
		if f.ID != "SUP-012" {
			continue
		}
		for _, id := range f.Artifacts {
			label[id] = "new since baseline"
			sev[id] = f.SevLabel
		}
	}
	return label, sev
}

// flaggedArtifacts maps a component ID to the worst severity reported about
// it. Findings name the components they concern explicitly, because a path is
// not an identity: three MCP servers configured in one file share a path, and
// flagging all of them because one is backdoored would be a lie the reader
// cannot check.
func flaggedArtifacts(r *model.Report) map[string]string {
	out := map[string]string{}
	worst := map[string]model.Severity{}
	for _, f := range r.Findings {
		if f.Severity < model.Medium || reviewOnly[f.ID] {
			continue
		}
		for _, id := range f.Artifacts {
			if f.Severity > worst[id] {
				worst[id] = f.Severity
				out[id] = f.Severity.String()
			}
		}
	}
	return out
}

func registryOf(id string) string {
	ref := strings.TrimPrefix(id, "ollama-model:")
	if i := strings.Index(ref, "/"); i > 0 {
		return ref[:i]
	}
	return ""
}
