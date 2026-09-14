package feed

import (
	"strconv"
	"strings"
)

// Version comparison exists because most published supply-chain compromises
// are not "this package is malicious" but "these versions of this otherwise
// ordinary package were backdoored". ultralytics 8.3.41 was a cryptominer;
// 8.3.40 was the library a hundred thousand people use. A list that cannot
// tell those apart would accuse every clean install, which is the same failure
// as missing the dirty one, pointed the other way.
//
// An exact-version list handles the small incidents. It does not handle an
// advisory that reads "fixed in 1.82.9" and covers every release before it, so
// ranges are expressed the way the advisories themselves are, with an
// introduced bound and a fixed bound.

// Range is a half-open interval of affected versions, in the OSV sense:
// a version is inside it when Introduced <= v < Fixed.
//
// Both bounds are optional. An empty Introduced means "from the first release";
// an empty Fixed means "no fixed release exists yet", which is the ordinary
// state for a package that was pulled from its registry rather than patched.
type Range struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// Verdict is the outcome of testing one component against one entry.
//
// The third state is the point. A version string this code cannot parse must
// not be silently dropped -- that would quietly turn a known-bad package into
// a clean result -- and it must not be reported as a match either, because
// nothing was actually established. It is surfaced as unresolved so the report
// can say "this needs a human" instead of guessing in either direction.
type Verdict int

const (
	// NoMatch means this entry does not apply.
	NoMatch Verdict = iota
	// Match means the entry applies and the report should say so.
	Match
	// Unresolved means the name matched but the version could not be
	// compared, so whether this install is affected is unknown.
	Unresolved
)

// parseVersion splits a version string into comparable parts.
//
// It is deliberately forgiving about the shapes real registries emit -- a
// leading "v", build metadata after "+", PEP 440 suffixes like ".post1" -- and
// deliberately unforgiving about anything else: a version it cannot make sense
// of returns ok=false rather than a best guess, because a wrong guess here is
// either a false accusation or a silent miss.
func parseVersion(s string) (nums []int, pre string, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, "", false
	}
	if s[0] == 'v' || s[0] == 'V' {
		s = s[1:]
	}
	// Build metadata never affects precedence.
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	// A prerelease or post-release suffix is kept, lower-cased, and compared
	// only when the numeric parts are equal.
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre, s = strings.ToLower(s[i+1:]), s[:i]
	}

	for _, part := range strings.Split(s, ".") {
		if part == "" {
			return nil, "", false
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			// A trailing non-numeric segment (1.2.3rc1, 8.3.41post1) is a
			// prerelease or post-release marker, not a number. Anything
			// earlier in the string is a version shape this code does not
			// understand, and it says so.
			lead := 0
			for lead < len(part) && part[lead] >= '0' && part[lead] <= '9' {
				lead++
			}
			if lead == 0 {
				if len(nums) == 0 {
					return nil, "", false
				}
				pre = joinPre(strings.ToLower(part), pre)
				break
			}
			n, err = strconv.Atoi(part[:lead])
			if err != nil {
				return nil, "", false
			}
			nums = append(nums, n)
			pre = joinPre(strings.ToLower(part[lead:]), pre)
			break
		}
		nums = append(nums, n)
	}
	if len(nums) == 0 {
		return nil, "", false
	}
	return nums, pre, true
}

func joinPre(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + "." + b
}

// CompareVersions orders two version strings. ok is false when either side is
// a shape this code will not guess at; callers must treat that as unknown
// rather than as equal, less or greater.
func CompareVersions(a, b string) (int, bool) {
	an, ap, aok := parseVersion(a)
	bn, bp, bok := parseVersion(b)
	if !aok || !bok {
		return 0, false
	}
	for i := 0; i < len(an) || i < len(bn); i++ {
		x, y := 0, 0
		if i < len(an) {
			x = an[i]
		}
		if i < len(bn) {
			y = bn[i]
		}
		if x != y {
			if x < y {
				return -1, true
			}
			return 1, true
		}
	}
	// Numerically equal. A release outranks its own prereleases: 1.2.0 is
	// newer than 1.2.0-rc1. Two different suffixes on the same numbers are
	// ordered lexically, which is right for rc1 < rc2 and harmless otherwise.
	switch {
	case ap == bp:
		return 0, true
	case ap == "":
		return 1, true
	case bp == "":
		return -1, true
	case ap < bp:
		return -1, true
	default:
		return 1, true
	}
}

// covers reports whether a version falls inside the range.
func (r Range) covers(v string) Verdict {
	if r.Introduced != "" {
		c, ok := CompareVersions(v, r.Introduced)
		if !ok {
			return Unresolved
		}
		if c < 0 {
			return NoMatch
		}
	}
	if r.Fixed != "" {
		c, ok := CompareVersions(v, r.Fixed)
		if !ok {
			return Unresolved
		}
		if c >= 0 {
			return NoMatch
		}
	}
	return Match
}

// Describe renders a range the way an advisory states it, for the report.
func (r Range) Describe() string {
	switch {
	case r.Introduced != "" && r.Fixed != "":
		return r.Introduced + " up to but not including " + r.Fixed
	case r.Introduced != "":
		return r.Introduced + " and later"
	case r.Fixed != "":
		return "every version before " + r.Fixed
	default:
		return "every version"
	}
}

// versionAffected tests one installed version against an entry's constraints.
//
// An entry with no constraints at all covers every version, which is the right
// default for a package that was pulled from its registry: there is no clean
// release to distinguish.
func (e Entry) versionAffected(v string) Verdict {
	if len(e.Versions) == 0 && len(e.Ranges) == 0 {
		return Match
	}
	unresolved := false
	for _, want := range e.Versions {
		c, ok := CompareVersions(v, want)
		if !ok {
			unresolved = true
			continue
		}
		if c == 0 {
			return Match
		}
	}
	for _, r := range e.Ranges {
		switch r.covers(v) {
		case Match:
			return Match
		case Unresolved:
			unresolved = true
		}
	}
	if unresolved {
		return Unresolved
	}
	return NoMatch
}

// constraintSummary describes what an entry covers, for a report that has to
// explain why an unpinned install is a problem without naming a version.
func (e Entry) constraintSummary() string {
	var parts []string
	if len(e.Versions) > 0 {
		parts = append(parts, strings.Join(e.Versions, ", "))
	}
	for _, r := range e.Ranges {
		parts = append(parts, r.Describe())
	}
	if len(parts) == 0 {
		return "every published version"
	}
	return strings.Join(parts, "; ")
}
