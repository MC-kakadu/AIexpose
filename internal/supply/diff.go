package supply

import (
	"fmt"
	"sort"
	"strings"
)

// ChangeType classifies a difference against the baseline.
type ChangeType string

const (
	Added    ChangeType = "added"
	Removed  ChangeType = "removed"
	Modified ChangeType = "modified"
)

// Change is one artifact that differs from the accepted state.
type Change struct {
	Type     ChangeType
	Current  *Artifact
	Previous *Artifact
	What     []string // human-readable description of what moved
}

// Diff compares the current inventory against the accepted baseline.
func Diff(baseline, current Inventory) []Change {
	prev := index(baseline.Artifacts)
	cur := index(current.Artifacts)

	var out []Change
	for id, c := range cur {
		p, existed := prev[id]
		if !existed {
			cc := c
			out = append(out, Change{Type: Added, Current: &cc})
			continue
		}
		if what := describe(p, c); len(what) > 0 {
			cc, pp := c, p
			out = append(out, Change{Type: Modified, Current: &cc, Previous: &pp, What: what})
		}
	}
	for id, p := range prev {
		if _, still := cur[id]; !still {
			pp := p
			out = append(out, Change{Type: Removed, Previous: &pp})
		}
	}

	sort.Slice(out, func(i, j int) bool {
		ri, rj := rank(out[i]), rank(out[j])
		if ri != rj {
			return ri < rj
		}
		if li, lj := label(out[i]), label(out[j]); li != lj {
			return li < lj
		}
		// Two components can share a label across installs; the ID cannot.
		return changeID(out[i]) < changeID(out[j])
	})
	return out
}

// describe explains how an artifact changed, in the order that matters most.
func describe(prev, cur Artifact) []string {
	var what []string
	if prev.Digest != cur.Digest {
		switch cur.Kind {
		case "mcp-server":
			what = append(what, fmt.Sprintf("launch command changed from %q to %q",
				prev.Detail["spec"], cur.Detail["spec"]))
		default:
			what = append(what, fmt.Sprintf("code changed (%d files now, %d before)",
				cur.FileCount, prev.FileCount))
		}
	}
	if prev.Detail["origin"] != cur.Detail["origin"] && cur.Detail["origin"] != "" {
		what = append(what, fmt.Sprintf("git origin changed to %s", cur.Detail["origin"]))
	}
	if prev.Detail["env_keys"] != cur.Detail["env_keys"] {
		what = append(what, fmt.Sprintf("environment keys changed from [%s] to [%s]",
			prev.Detail["env_keys"], cur.Detail["env_keys"]))
	}
	if n := newIndicators(prev, cur); len(n) > 0 {
		what = append(what, "new risk indicators: "+strings.Join(n, ", "))
	}
	return what
}

// newIndicators lists indicator IDs present now but absent at baseline. An
// artifact that gains one of these after you installed it is the exact shape
// of a supply chain rug-pull.
func newIndicators(prev, cur Artifact) []string {
	had := map[string]bool{}
	for _, i := range prev.Indicators {
		had[i.ID] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, i := range cur.Indicators {
		if !had[i.ID] && !seen[i.ID] {
			seen[i.ID] = true
			out = append(out, i.ID)
		}
	}
	sort.Strings(out)
	return out
}

// HasNewIndicator reports whether a modified artifact gained an indicator.
func (c Change) HasNewIndicator() bool {
	for _, w := range c.What {
		if strings.HasPrefix(w, "new risk indicators:") {
			return true
		}
	}
	return false
}

// Label names the artifact a change refers to.
func (c Change) Label() string { return label(c) }

func label(c Change) string {
	if c.Current != nil {
		return c.Current.Kind + " " + c.Current.Name
	}
	if c.Previous != nil {
		return c.Previous.Kind + " " + c.Previous.Name
	}
	return "unknown"
}

// changeID is the stable identity of whichever side of the change exists.
func changeID(c Change) string {
	if c.Current != nil {
		return c.Current.ID
	}
	if c.Previous != nil {
		return c.Previous.ID
	}
	return ""
}

func rank(c Change) int {
	switch {
	case c.Type == Modified && c.HasNewIndicator():
		return 0
	case c.Type == Modified:
		return 1
	case c.Type == Added:
		return 2
	default:
		return 3
	}
}

func index(as []Artifact) map[string]Artifact {
	m := make(map[string]Artifact, len(as))
	for _, a := range as {
		m[a.ID] = a
	}
	return m
}
