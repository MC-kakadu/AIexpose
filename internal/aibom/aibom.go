// Package aibom writes the machine's AI inventory as a CycloneDX 1.6 SBOM.
//
// This is the one output of this tool that is meant to be read by something
// other than a person. A scan report answers "is this machine exposed"; an
// AI-BOM answers "what AI components are on it", in a format an SBOM platform,
// a procurement questionnaire or an auditor already accepts. The scanner
// already knows every part of the answer -- it fingerprints these components on
// every run to detect drift -- so publishing it costs nothing new and turns a
// local report into evidence someone else can ingest.
//
// Spec version 1.6 rather than the current 1.7, because 1.6 is what SBOM
// tooling reads today and nothing here needs a 1.7 field.
//
// What is deliberately absent: model cards. CycloneDX can carry training data,
// performance metrics and ethical considerations for a model, and this scanner
// knows none of those -- it reads files on a disk. Emitting empty or guessed
// model card fields would make the document look more authoritative than the
// evidence behind it.
package aibom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/MC-kakadu/AIexpose/internal/model"
	"github.com/MC-kakadu/AIexpose/internal/supply"
)

const specVersion = "1.6"

// Document is a CycloneDX BOM. Only the fields this tool can honestly fill are
// declared, so an empty value never reaches the output as a guess.
type Document struct {
	Schema       string      `json:"$schema"`
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version      int         `json:"version"`
	Metadata     Metadata    `json:"metadata"`
	Components   []Component `json:"components"`
	Services     []Service   `json:"services,omitempty"`
}

type Metadata struct {
	Timestamp  string     `json:"timestamp"`
	Tools      Tools      `json:"tools"`
	Component  *Component `json:"component,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}

type Tools struct {
	Components []Component `json:"components"`
}

type Component struct {
	Type               string     `json:"type"`
	BOMRef             string     `json:"bom-ref,omitempty"`
	Group              string     `json:"group,omitempty"`
	Name               string     `json:"name"`
	Version            string     `json:"version,omitempty"`
	Publisher          string     `json:"publisher,omitempty"`
	Description        string     `json:"description,omitempty"`
	PURL               string     `json:"purl,omitempty"`
	Hashes             []Hash     `json:"hashes,omitempty"`
	ExternalReferences []ExtRef   `json:"externalReferences,omitempty"`
	Properties         []Property `json:"properties,omitempty"`
}

type Hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type ExtRef struct {
	Type    string `json:"type"`
	URL     string `json:"url"`
	Comment string `json:"comment,omitempty"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Service struct {
	BOMRef        string     `json:"bom-ref,omitempty"`
	Group         string     `json:"group,omitempty"`
	Name          string     `json:"name"`
	Description   string     `json:"description,omitempty"`
	Endpoints     []string   `json:"endpoints,omitempty"`
	Authenticated *bool      `json:"authenticated,omitempty"`
	TrustBoundary *bool      `json:"x-trust-boundary,omitempty"`
	Properties    []Property `json:"properties,omitempty"`
}

// Write renders the BOM as indented JSON.
func Write(w io.Writer, r *model.Report, inv supply.Inventory) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(Build(r, inv))
}

// Build assembles the document.
func Build(r *model.Report, inv supply.Inventory) Document {
	components := make([]Component, 0, len(inv.Artifacts))
	for _, a := range inv.Artifacts {
		components = append(components, componentFor(a))
	}
	sort.Slice(components, func(i, j int) bool { return components[i].BOMRef < components[j].BOMRef })

	doc := Document{
		Schema:      "http://cyclonedx.org/schema/bom-" + specVersion + ".schema.json",
		BOMFormat:   "CycloneDX",
		SpecVersion: specVersion,
		Version:     1,
		Metadata: Metadata{
			Timestamp: r.Started.UTC().Format(time.RFC3339),
			Tools:     Tools{Components: []Component{toolComponent(r)}},
			Component: &Component{
				Type: "platform", BOMRef: "host:" + r.Host,
				Name: r.Host, Description: "AI components installed on this machine",
				Properties: []Property{
					{Name: "aiexpose:os", Value: r.OS},
					{Name: "aiexpose:arch", Value: r.Arch},
				},
			},
			Properties: metadataProperties(r, inv),
		},
		Components: components,
		Services:   services(r),
	}
	doc.SerialNumber = serial(doc)
	return doc
}

func toolComponent(r *model.Report) Component {
	c := Component{
		Type: "application", BOMRef: "tool:" + r.Tool + "@" + r.Version,
		Name: r.Tool, Version: r.Version,
		ExternalReferences: []ExtRef{
			{Type: "website", URL: "https://github.com/MC-kakadu/AIexpose"},
		},
	}
	if r.Attest.SelfDigest != "" {
		c.Hashes = []Hash{{Alg: "SHA-256", Content: r.Attest.SelfDigest}}
	}
	if r.Attest.Profile != "" {
		c.Properties = append(c.Properties, Property{Name: "aiexpose:build-profile", Value: r.Attest.Profile})
	}
	if r.Attest.RuleVersion != "" {
		c.Properties = append(c.Properties, Property{Name: "aiexpose:rule-version", Value: r.Attest.RuleVersion})
	}
	return c
}

// metadataProperties record the limits of the document, next to the document.
// A consumer that reads only the component list should still be able to find
// out that weights were not hashed and that the inventory was bounded.
func metadataProperties(r *model.Report, inv supply.Inventory) []Property {
	p := []Property{
		{Name: "aiexpose:scan-started", Value: r.Started.UTC().Format(time.RFC3339)},
		{Name: "aiexpose:scope", Value: "components installed for the user running the scan; system-wide installations owned by other users are not visible"},
		{Name: "aiexpose:model-weights-hashed", Value: "false"},
		{Name: "aiexpose:model-card-data", Value: "absent: this inventory is built by reading files on disk and has no training, performance or fairness data"},
	}
	for _, root := range inv.Roots {
		p = append(p, Property{Name: "aiexpose:inventory-root", Value: root})
	}
	for _, s := range inv.Skipped {
		p = append(p, Property{Name: "aiexpose:incomplete", Value: s})
	}
	return p
}

func componentFor(a supply.Artifact) Component {
	c := Component{Type: cdxType(a.Kind), BOMRef: a.ID, Name: a.Name}
	c.Properties = append(c.Properties,
		Property{Name: "aiexpose:kind", Value: a.Kind},
		Property{Name: "aiexpose:path", Value: a.Path},
	)
	if a.Digest != "" {
		// The digest is this tool's own fingerprint over the component's
		// executable and config files, not a hash of a distributed archive.
		// Saying which is the difference between an auditable number and a
		// number that looks like one.
		c.Hashes = []Hash{{Alg: "SHA-256", Content: a.Digest}}
		c.Properties = append(c.Properties, Property{
			Name:  "aiexpose:digest-scope",
			Value: "sha256 over the component's code and config files and their paths, computed by aiexpose",
		})
	}
	if a.FileCount > 0 {
		c.Properties = append(c.Properties, Property{Name: "aiexpose:file-count", Value: fmt.Sprint(a.FileCount)})
	}

	switch a.Kind {
	case "ollama-model":
		fillModel(&c, a)
	case "mcp-server":
		fillMCP(&c, a)
	default:
		if origin := a.Detail["origin"]; origin != "" {
			c.ExternalReferences = append(c.ExternalReferences, ExtRef{Type: "vcs", URL: origin})
		}
	}

	// Everything else the inventory knows, verbatim, so the BOM never holds
	// less than the report it came from.
	for _, k := range sortedKeys(a.Detail) {
		if skipDetail[k] {
			continue
		}
		c.Properties = append(c.Properties, Property{Name: "aiexpose:" + strings.ReplaceAll(k, "_", "-"), Value: a.Detail[k]})
	}
	return c
}

// skipDetail holds keys already rendered as first-class fields.
var skipDetail = map[string]bool{
	"origin": true, "package": true, "package_version": true,
}

func fillModel(c *Component, a supply.Artifact) {
	// The artifact ID carries the full reference: registry/namespace/name:tag.
	ref := strings.TrimPrefix(a.ID, "ollama-model:")
	if i := strings.Index(ref, "/"); i > 0 {
		c.Publisher = ref[:i]
		rest := ref[i+1:]
		if j := strings.Index(rest, "/"); j > 0 {
			c.Group = rest[:j]
		}
	}
	if i := strings.LastIndex(a.Name, ":"); i > 0 {
		c.Version = a.Name[i+1:]
	}
	c.Description = "Ollama model"
	if c.Publisher != "" {
		c.ExternalReferences = append(c.ExternalReferences, ExtRef{
			Type: "distribution", URL: "https://" + c.Publisher,
			Comment: "registry the model was pulled from",
		})
	}
}

func fillMCP(c *Component, a supply.Artifact) {
	c.Description = "MCP server"
	name, ver := a.Detail["package"], a.Detail["package_version"]
	if name == "" {
		return
	}
	c.Version = ver
	if eco := ecosystem(a.Detail["spec"]); eco != "" {
		c.PURL = "pkg:" + eco + "/" + name
		if ver != "" {
			c.PURL += "@" + ver
		}
	}
	c.Properties = append(c.Properties, Property{Name: "aiexpose:package", Value: name})
	if ver == "" {
		c.Properties = append(c.Properties, Property{
			Name:  "aiexpose:version-pinned",
			Value: "false: this server resolves its version at launch, so the BOM cannot state what will run",
		})
	}
}

// ecosystem maps the launcher a server uses to a purl type. An unrecognised
// launcher yields no purl at all rather than a guessed one.
func ecosystem(spec string) string {
	fields := strings.Fields(spec)
	if len(fields) == 0 {
		return ""
	}
	runner := strings.ToLower(baseName(fields[0]))
	switch runner {
	case "npx", "npx.cmd", "bunx", "pnpm":
		return "npm"
	case "uvx", "pipx", "uv":
		return "pypi"
	}
	return ""
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func cdxType(kind string) string {
	switch kind {
	case "ollama-model":
		return "machine-learning-model"
	case "mcp-server":
		// A separate process with its own lifecycle.
		return "application"
	}
	// Custom nodes and agent skills are loaded into a host application.
	return "library"
}

// services records what was found listening, with the two facts an SBOM
// consumer actually acts on: is it authenticated, and does it cross a trust
// boundary.
func services(r *model.Report) []Service {
	var out []Service
	for _, s := range r.Services {
		auth := !s.NoAuth
		crosses := s.ExposureS != "loopback"
		svc := Service{
			BOMRef:        fmt.Sprintf("service:%s:%d", strings.ToLower(s.Name), s.Listener.Port),
			Name:          s.Name,
			Endpoints:     []string{fmt.Sprintf("http://%s:%d", s.Listener.Addr, s.Listener.Port)},
			TrustBoundary: &crosses,
			Properties: []Property{
				{Name: "aiexpose:kind", Value: s.Kind},
				{Name: "aiexpose:exposure", Value: s.ExposureS},
			},
		}
		// authenticated is only stated when the API was actually probed.
		// Leaving it out is more honest than defaulting it to true.
		if s.Confirmed {
			svc.Authenticated = &auth
			svc.Description = "identified by HTTP fingerprint"
		} else {
			svc.Description = "identified by listening port only; its API was not probed"
			svc.Properties = append(svc.Properties, Property{
				Name: "aiexpose:authenticated", Value: "unknown: the service did not answer a fingerprint request",
			})
		}
		out = append(out, svc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BOMRef < out[j].BOMRef })
	return out
}

// serial derives the BOM's identifier from its own contents, so re-scanning an
// unchanged machine produces the same serial number and two BOMs can be
// diffed. The scan timestamp is part of the input, so every run still gets a
// distinct identifier.
func serial(d Document) string {
	d.SerialNumber = ""
	b, err := json.Marshal(d)
	if err != nil {
		b = []byte(d.Metadata.Timestamp)
	}
	sum := sha256.Sum256(b)
	h := hex.EncodeToString(sum[:])
	// Shape the digest as a v4 UUID so schema validators accept it. The bits
	// are derived, not random; the version nibble says v4 because that is the
	// only value the format allows for a non-namespaced identifier.
	return fmt.Sprintf("urn:uuid:%s-%s-4%s-%s%s-%s",
		h[0:8], h[8:12], h[13:16], string("89ab"[sum[8]%4]), h[17:20], h[20:32])
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
