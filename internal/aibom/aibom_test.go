package aibom

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/MC-kakadu/AIexpose/internal/model"
	"github.com/MC-kakadu/AIexpose/internal/supply"
)

func fixture() (*model.Report, supply.Inventory) {
	r := &model.Report{
		Tool: "aiexpose", Version: "9.9.9", Host: "box", OS: "linux", Arch: "amd64",
		Started: time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC),
		Attest: model.Attestation{
			Version: "9.9.9", Profile: "default",
			SelfDigest: strings.Repeat("f", 64), RuleVersion: "2026.09.10",
		},
		Services: []model.Service{
			{Name: "Ollama", Kind: "llm-server", ExposureS: "all-interfaces",
				Confirmed: true, NoAuth: true,
				Listener: model.Listener{Addr: "0.0.0.0", Port: 11434}},
			{Name: "Mystery", Kind: "unknown", ExposureS: "loopback",
				Listener: model.Listener{Addr: "127.0.0.1", Port: 9999}},
		},
	}
	inv := supply.Inventory{Artifacts: []supply.Artifact{
		{Kind: "ollama-model", ID: "ollama-model:registry.ollama.ai/library/llama3:8b",
			Name: "llama3:8b", Path: "/m/llama3", Digest: strings.Repeat("a", 64), FileCount: 3,
			Detail: map[string]string{"layers": "weights,system-prompt", "size": "4.7 GB"}},
		{Kind: "mcp-server", ID: "mcp-server:postmark", Name: "postmark", Path: "/c.json",
			Digest: strings.Repeat("b", 64),
			Detail: map[string]string{"package": "postmark-mcp", "package_version": "1.0.16",
				"spec": "npx -y postmark-mcp@1.0.16", "transport": "stdio"}},
		{Kind: "mcp-server", ID: "mcp-server:fetcher", Name: "fetcher", Path: "/c.json",
			Digest: strings.Repeat("c", 64),
			Detail: map[string]string{"package": "mcp-server-fetch",
				"spec": "uvx mcp-server-fetch", "transport": "stdio"}},
		{Kind: "comfy-node", ID: "comfy-node:thing", Name: "thing", Path: "/n/thing",
			Digest: strings.Repeat("d", 64),
			Detail: map[string]string{"origin": "https://github.com/a/thing.git"}},
	}}
	return r, inv
}

func build(t *testing.T) map[string]any {
	t.Helper()
	r, inv := fixture()
	var buf bytes.Buffer
	if err := Write(&buf, r, inv); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	return got
}

func TestDocumentShape(t *testing.T) {
	d := build(t)
	if d["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v", d["bomFormat"])
	}
	if d["specVersion"] != "1.6" {
		t.Errorf("specVersion = %v", d["specVersion"])
	}
	if d["version"].(float64) != 1 {
		t.Errorf("version = %v", d["version"])
	}
	serial := d["serialNumber"].(string)
	if !regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(serial) {
		t.Errorf("serialNumber %q does not match the schema's UUID pattern", serial)
	}
}

// Two scans of the same machine in the same state must produce the same
// document, so a reader can diff yesterday's BOM against today's and see only
// what actually changed.
func TestSerialIsDerivedFromContent(t *testing.T) {
	a, b := build(t), build(t)
	if a["serialNumber"] != b["serialNumber"] {
		t.Fatal("two identical scans produced different serial numbers")
	}

	r, inv := fixture()
	inv.Artifacts[0].Digest = strings.Repeat("9", 64)
	var buf bytes.Buffer
	_ = Write(&buf, r, inv)
	var changed map[string]any
	_ = json.Unmarshal(buf.Bytes(), &changed)
	if changed["serialNumber"] == a["serialNumber"] {
		t.Error("a changed component did not change the serial number")
	}
}

func TestComponentTypesAndPURLs(t *testing.T) {
	d := build(t)
	byRef := map[string]map[string]any{}
	for _, c := range d["components"].([]any) {
		m := c.(map[string]any)
		byRef[m["bom-ref"].(string)] = m
	}

	cases := []struct{ ref, typ, purl string }{
		{"ollama-model:registry.ollama.ai/library/llama3:8b", "machine-learning-model", ""},
		{"mcp-server:postmark", "application", "pkg:npm/postmark-mcp@1.0.16"},
		{"mcp-server:fetcher", "application", "pkg:pypi/mcp-server-fetch"},
		{"comfy-node:thing", "library", ""},
	}
	for _, c := range cases {
		got, ok := byRef[c.ref]
		if !ok {
			t.Errorf("%s is missing from the BOM", c.ref)
			continue
		}
		if got["type"] != c.typ {
			t.Errorf("%s type = %v, want %s", c.ref, got["type"], c.typ)
		}
		if p, _ := got["purl"].(string); p != c.purl {
			t.Errorf("%s purl = %q, want %q", c.ref, p, c.purl)
		}
	}

	m := byRef["ollama-model:registry.ollama.ai/library/llama3:8b"]
	if m["publisher"] != "registry.ollama.ai" || m["group"] != "library" || m["version"] != "8b" {
		t.Errorf("model reference was not split correctly: %+v", m)
	}
}

// The digest in this BOM is this tool's own fingerprint, not a hash any
// registry published. Saying which is the difference between an auditable
// number and one that only looks like it.
func TestDigestScopeIsStated(t *testing.T) {
	d := build(t)
	for _, c := range d["components"].([]any) {
		m := c.(map[string]any)
		if _, ok := m["hashes"]; !ok {
			continue
		}
		if !hasProperty(m, "aiexpose:digest-scope") {
			t.Errorf("%v carries a hash with no statement of what it covers", m["bom-ref"])
		}
	}
}

// An unprobed service must not be reported as authenticated. Defaulting the
// field would turn "we do not know" into "it is fine".
func TestAuthenticatedOnlyWhenProbed(t *testing.T) {
	d := build(t)
	svcs := map[string]map[string]any{}
	for _, s := range d["services"].([]any) {
		m := s.(map[string]any)
		svcs[m["name"].(string)] = m
	}

	ollama := svcs["Ollama"]
	if ollama["authenticated"] != false {
		t.Errorf("Ollama authenticated = %v, want false", ollama["authenticated"])
	}
	if ollama["x-trust-boundary"] != true {
		t.Errorf("an all-interfaces service should cross a trust boundary")
	}

	mystery := svcs["Mystery"]
	if _, ok := mystery["authenticated"]; ok {
		t.Error("an unprobed service was given an authenticated verdict")
	}
	if !hasProperty(mystery, "aiexpose:authenticated") {
		t.Error("an unprobed service does not say that its auth state is unknown")
	}
}

// The document has to disclose its own limits, or a consumer reading only the
// component list will assume the weights were verified.
func TestLimitsAreDisclosed(t *testing.T) {
	d := build(t)
	meta := d["metadata"].(map[string]any)
	for _, want := range []string{"aiexpose:model-weights-hashed", "aiexpose:model-card-data", "aiexpose:scope"} {
		if !hasProperty(meta, want) {
			t.Errorf("metadata does not declare %s", want)
		}
	}
	tools := meta["tools"].(map[string]any)["components"].([]any)
	if len(tools) != 1 {
		t.Fatalf("tools has %d entries, want the scanner", len(tools))
	}
	tool := tools[0].(map[string]any)
	h := tool["hashes"].([]any)[0].(map[string]any)
	if h["alg"] != "SHA-256" || len(h["content"].(string)) != 64 {
		t.Errorf("tool hash = %+v", h)
	}
}

func TestEmptyInventoryStillProducesAValidDocument(t *testing.T) {
	r := &model.Report{Tool: "aiexpose", Version: "1", Host: "h", Started: time.Now()}
	var buf bytes.Buffer
	if err := Write(&buf, r, supply.Inventory{}); err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := json.Unmarshal(buf.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if d["components"] == nil {
		t.Error("components is null rather than an empty array")
	}
}

func hasProperty(m map[string]any, name string) bool {
	props, ok := m["properties"].([]any)
	if !ok {
		return false
	}
	for _, p := range props {
		if p.(map[string]any)["name"] == name {
			return true
		}
	}
	return false
}
