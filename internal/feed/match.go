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

	// Unresolved marks a hit where the name matched a known-bad package but
	// the installed version could not be compared against the entry's
	// constraints. It is not an accusation and must never be reported as one:
	// the honest statement is that this needs a person to look, and a report
	// that rendered it as a confirmed match would be making up the half it
	// could not determine.
	Unresolved bool
}

// Match returns every feed entry that applies to the given components.
func (f Feed) Match(components []Component) []Hit {
	var hits []Hit
	for _, e := range f.Entries {
		for _, c := range components {
			why, v := e.matches(c)
			switch v {
			case Match:
				hits = append(hits, Hit{Entry: e, Component: c, Why: why})
			case Unresolved:
				hits = append(hits, Hit{Entry: e, Component: c, Why: why, Unresolved: true})
			}
		}
	}
	return hits
}

func (e Entry) matches(c Component) (string, Verdict) {
	switch e.Kind {
	case Package:
		if c.Package == "" || !strings.EqualFold(c.Package, e.Match) {
			return "", NoMatch
		}
		// An unpinned launch spec fetches whatever the registry serves today,
		// so it can resolve to an affected version at any moment. That is a
		// real finding regardless of which version happens to be on disk.
		if c.Version == "" {
			if len(e.Versions) == 0 && len(e.Ranges) == 0 {
				return "package " + c.Package + " (version unpinned, so any published version can be fetched)", Match
			}
			return "package " + c.Package + " is unpinned, so it can resolve to an affected version (" +
				e.constraintSummary() + ")", Match
		}
		switch e.versionAffected(c.Version) {
		case Match:
			if len(e.Versions) == 0 && len(e.Ranges) == 0 {
				return "package " + c.Package + "@" + c.Version, Match
			}
			return "package " + c.Package + "@" + c.Version + " falls within the affected versions (" +
				e.constraintSummary() + ")", Match
		case Unresolved:
			return "package " + c.Package + " is on the known-bad list for " + e.constraintSummary() +
				", but the installed version " + c.Version + " could not be compared against that", Unresolved
		}
		return "", NoMatch

	case ArtifactDigest:
		if c.Digest != "" && strings.EqualFold(c.Digest, e.Match) {
			return "the contents of " + c.Name + " hash to a known-bad digest", Match
		}

	case FileDigest:
		for _, d := range c.FileDigests {
			if strings.EqualFold(d, e.Match) {
				return "a file inside " + c.Name + " hashes to a known-bad digest", Match
			}
		}

	case NodeName:
		if strings.EqualFold(c.Name, e.Match) {
			return "the component is named " + c.Name, Match
		}
	}
	return "", NoMatch
}
