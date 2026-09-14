package feed

import (
	"strings"
)

// Component is what the scanner found installed, reduced to the fields the
// feed matches on. Keeping this separate from the inventory type means the
// feed never depends on how components are discovered.
type Component struct {
	// ID is the inventory's stable identifier, carried through so a hit can
	// name the exact component rather than the file it was configured in.
	ID          string
	Kind        string // comfy-node | mcp-server | agent-skill
	Name        string
	Path        string
	Digest      string
	FileDigests []string
	Package     string // registry package name, for MCP servers
	Version     string // empty when the launch spec is unpinned
}

// Hit pairs a feed entry with the component it matched.
type Hit struct {
	Entry     Entry
	Component Component
	// Why explains which property matched, so the report never says
	// "known malicious" without saying how it decided that.
	Why string
}

// Match returns every feed entry that applies to the given components.
func (f Feed) Match(components []Component) []Hit {
	var hits []Hit
	for _, e := range f.Entries {
		for _, c := range components {
			if why, ok := e.matches(c); ok {
				hits = append(hits, Hit{Entry: e, Component: c, Why: why})
			}
		}
	}
	return hits
}

func (e Entry) matches(c Component) (string, bool) {
	switch e.Kind {
	case Package:
		if c.Package == "" || !strings.EqualFold(c.Package, e.Match) {
			return "", false
		}
		if len(e.Versions) == 0 {
			// Every published version is considered bad. This is the right
			// default for a package that was pulled from its registry.
			if c.Version == "" {
				return "package " + c.Package + " (version unpinned, so any published version can be fetched)", true
			}
			return "package " + c.Package + "@" + c.Version, true
		}
		// An unpinned server can fetch any version, including a listed one.
		if c.Version == "" {
			return "package " + c.Package + " is unpinned and can resolve to a listed bad version", true
		}
		for _, v := range e.Versions {
			if v == c.Version {
				return "package " + c.Package + "@" + c.Version, true
			}
		}
		return "", false

	case ArtifactDigest:
		if c.Digest != "" && strings.EqualFold(c.Digest, e.Match) {
			return "the contents of " + c.Name + " hash to a known-bad digest", true
		}

	case FileDigest:
		for _, d := range c.FileDigests {
			if strings.EqualFold(d, e.Match) {
				return "a file inside " + c.Name + " hashes to a known-bad digest", true
			}
		}

	case NodeName:
		if strings.EqualFold(c.Name, e.Match) {
			return "the component is named " + c.Name, true
		}
	}
	return "", false
}
