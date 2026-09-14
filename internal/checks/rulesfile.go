package checks

import (
	"os"
	"path/filepath"
	"strings"
)

// repoRulesPath is where the signed rule document lives inside a source
// checkout. It is not the name a release uses, and that difference is the
// whole reason this file exists.
const repoRulesPath = "internal/feed/data/feed.json"

// releaseRulesName is the name the rule file has when it ships beside a
// downloaded binary.
const releaseRulesName = "aiexpose-rules.json"

// rulesFileToSuggest returns a path to a rule file that is actually present,
// so the advice names something the reader can act on.
//
// Someone who cloned the repository and ran "go build" has no
// aiexpose-rules.json anywhere -- that name belongs to a release asset. They
// do have internal/feed/data/feed.json, sitting in the tree they just built
// from. Telling them to install a file that does not exist, when the one that
// does is two directories away, is the same class of unhelpfulness as
// reporting a check as passed when it never ran: the sentence is well-formed
// and useless to the person reading it.
//
// The release name is returned when nothing is found, because that is the
// right instruction for the much larger group who downloaded a binary.
func rulesFileToSuggest() string {
	for _, p := range candidateRulesFiles() {
		if p == "" {
			continue
		}
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			if _, err := os.Stat(p + ".sig"); err == nil {
				return shortestPath(p)
			}
		}
	}
	return releaseRulesName
}

func candidateRulesFiles() []string {
	var out []string
	if wd, err := os.Getwd(); err == nil {
		out = append(out,
			filepath.Join(wd, releaseRulesName),
			filepath.Join(wd, filepath.FromSlash(repoRulesPath)))
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		out = append(out,
			filepath.Join(dir, releaseRulesName),
			filepath.Join(dir, filepath.FromSlash(repoRulesPath)))
	}
	return out
}

// shortestPath prefers a path relative to the working directory, because that
// is what the reader can paste. An absolute path to a file three directories
// below where they are standing is correct and awkward.
func shortestPath(p string) string {
	wd, err := os.Getwd()
	if err != nil {
		return p
	}
	rel, err := filepath.Rel(wd, p)
	if err != nil || len(rel) >= len(p) || strings.HasPrefix(rel, "..") {
		return p
	}
	return rel
}
