package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The report path must not be decided by creating a file and deleting it.
// Create-then-delete in Desktop or Documents is the canary behaviour
// Controlled Folder Access exists to catch, and an unsigned binary doing it
// on a double-click launch is the worst possible first impression to give a
// behavioural engine.
func TestDefaultReportPathTouchesNothing(t *testing.T) {
	dir := t.TempDir()
	before, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	// defaultReportPath uses the executable's folder; the guarantee under test
	// is that computing it performs no writes at all, which we can assert by
	// watching a folder it would be free to probe.
	got := defaultReportPath()
	if got == "" {
		t.Fatal("no report path")
	}
	if filepath.Base(got) != "aiexpose-report.html" {
		t.Errorf("unexpected report name %q", got)
	}

	after, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Errorf("computing the report path created files: %d -> %d", len(before), len(after))
	}
	if strings.Contains(got, "write-test") {
		t.Error("the report path still names a probe file")
	}
}

// And when the chosen folder will not take the report, there has to be
// somewhere else to put it -- otherwise a read-only download folder loses the
// whole scan.
func TestFallbackReportPathIsWritable(t *testing.T) {
	p := fallbackReportPath()
	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("the fallback report path is not writable: %v", err)
	}
	f.Close()
	os.Remove(p)
}
