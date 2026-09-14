package feed

import (
	"fmt"
	"strings"
)

// Validation exists because every way an entry can be wrong is silent.
//
// A version constraint on a kind that has no version to compare is ignored, so
// an entry meant to name four bad releases of ultralytics accuses every
// install of it. A version string this code cannot parse never equals anything,
// so an entry meant to catch a backdoor catches nothing and the report says the
// machine is clean. A severity label with a typo quietly becomes Info, so a
// critical finding is filed as a note. None of these produce an error at any
// point in a scan; they produce a confident answer that is wrong.
//
// So the feed is checked before it is trusted, and the shipped feed is checked
// in the test suite, where a broken entry fails the build rather than a user's
// report.

// Problem is one thing wrong with a feed entry.
type Problem struct {
	EntryID string
	Message string
}

func (p Problem) Error() string {
	if p.EntryID == "" {
		return p.Message
	}
	return p.EntryID + ": " + p.Message
}

var knownSeverities = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true, "info": true,
}

// Validate reports everything wrong with the feed's entries. An empty result
// means every entry can do what its author intended.
func (f Feed) Validate() []Problem {
	var out []Problem
	seen := map[string]bool{}

	for _, e := range f.Entries {
		add := func(format string, args ...any) {
			out = append(out, Problem{EntryID: e.ID, Message: fmt.Sprintf(format, args...)})
		}

		if strings.TrimSpace(e.ID) == "" {
			add("the entry has no id, so a report cannot cite it")
		} else if seen[e.ID] {
			add("a second entry uses this id")
		} else {
			seen[e.ID] = true
		}

		switch e.Kind {
		case Package, ArtifactDigest, FileDigest, NodeName:
		case "":
			add("the entry has no kind, so nothing will ever match it")
		default:
			add("kind %q is not one this build knows, so the entry will never match", e.Kind)
		}

		if strings.TrimSpace(e.Match) == "" {
			add("the entry has nothing to match on")
		}
		if strings.TrimSpace(e.Title) == "" {
			add("the entry has no title, so a finding would have nothing to say")
		}
		if s := strings.ToLower(strings.TrimSpace(e.Severity)); !knownSeverities[s] {
			// An unrecognised label silently becomes Info, which files a
			// critical finding as a note.
			add("severity %q is not recognised and would quietly be treated as info", e.Severity)
		}

		hasConstraints := len(e.Versions) > 0 || len(e.Ranges) > 0
		if hasConstraints && e.Kind != Package {
			// This is the bug this check was written for. A digest is its own
			// version, and a component matched by directory name carries no
			// version at all, so a constraint on those kinds is not a
			// narrower rule -- it is a rule the matcher throws away, leaving
			// one that matches everything.
			add("kind %q cannot compare versions, so these version constraints would be ignored "+
				"and the entry would match every install", e.Kind)
		}

		for _, v := range e.Versions {
			if _, _, ok := parseVersion(v); !ok {
				add("version %q cannot be parsed, so it will never match anything", v)
			}
		}
		for i, r := range e.Ranges {
			if r.Introduced == "" && r.Fixed == "" {
				add("version range %d has no bounds; leave the list empty to mean every version", i+1)
				continue
			}
			if r.Introduced != "" {
				if _, _, ok := parseVersion(r.Introduced); !ok {
					add("range %d has an unparseable introduced bound %q", i+1, r.Introduced)
					continue
				}
			}
			if r.Fixed != "" {
				if _, _, ok := parseVersion(r.Fixed); !ok {
					add("range %d has an unparseable fixed bound %q", i+1, r.Fixed)
					continue
				}
			}
			if r.Introduced != "" && r.Fixed != "" {
				if c, ok := CompareVersions(r.Introduced, r.Fixed); ok && c >= 0 {
					add("range %d is empty: introduced %s is not below fixed %s", i+1, r.Introduced, r.Fixed)
				}
			}
		}
	}
	return out
}
