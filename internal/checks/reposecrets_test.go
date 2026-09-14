package checks

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The credential detector is pointed at its own repository.
//
// A push of this project was rejected by GitHub's secret scanning because a
// test fixture in this package was a literal Slack bot token shape. It was not
// a real token, but it was a real incident: the fixture corpus of a credential
// detector is, by construction, the thing every other scanner is looking for.
//
// So the rule is that no file in this repository may contain a run of bytes
// that this tool would itself report as a credential. Fixtures are assembled
// from pieces at runtime instead. That keeps the tests realistic without
// putting a scanner-matching string on disk, and it means a contributor finds
// out here rather than from a rejected push.
func TestNoFileInThisRepositoryLooksLikeItHoldsACredential(t *testing.T) {
	loadShippedRules(t)

	root := repoRoot(t)
	var offences []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "dist", "dist-minimal", "dist-offline", "virusHashDb", "node_modules":
				return fs.SkipDir
			}
			return nil
		}
		switch filepath.Ext(path) {
		case ".go", ".md", ".yml", ".yaml", ".json", ".sh", ".bat", ".mod":
		default:
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil || len(body) > 4<<20 {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		for i, line := range strings.Split(string(body), "\n") {
			for _, h := range scanLine(rel, i+1, line) {
				offences = append(offences,
					h.vendor+" key shape at "+rel+":"+itoa(i+1)+"  "+h.masked)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(offences) > 0 {
		t.Fatalf("this repository contains %d string(s) that this tool reports as credentials.\n"+
			"Assemble the fixture from pieces at runtime instead of writing it as one literal:\n  %s",
			len(offences), strings.Join(offences, "\n  "))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// repoRoot walks up until it finds go.mod, so the test does not depend on
// where the package sits in the tree.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the working directory")
		}
		dir = parent
	}
}
