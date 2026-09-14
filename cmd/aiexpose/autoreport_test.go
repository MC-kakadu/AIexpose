package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The report is written where the person is standing, not where the binary
// happens to live. A binary installed with "go install" sits in ~/go/bin, and
// nobody looks there for a scan result.
func TestReportGoesToTheWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	got := defaultReportPath()
	if filepath.Dir(got) != dir {
		t.Errorf("report path = %q, want it inside the working directory %q", got, dir)
	}
	if filepath.Base(got) != "aiexpose-report.html" {
		t.Errorf("unexpected report name %q", got)
	}
}

// Deciding the path must not write anything: create-then-delete in a folder
// Windows protects is the canary behaviour Controlled Folder Access exists to
// catch.
func TestChoosingTheReportPathWritesNothing(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	before, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defaultReportPath()
	after, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Errorf("choosing the report path created files: %d -> %d", len(before), len(after))
	}
}

// And there has to be somewhere else to put it when that folder will not take
// it -- a read-only checkout, or a binary run from a mounted image.
func TestFallbackReportPathIsWritableAndDifferent(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	fb := fallbackReportPath()
	if filepath.Dir(fb) == dir {
		t.Error("the fallback is the same directory that just failed")
	}
	f, err := os.Create(fb)
	if err != nil {
		t.Fatalf("fallback path is not writable: %v", err)
	}
	f.Close()
	os.Remove(fb)
	if !strings.HasSuffix(fb, "aiexpose-report.html") {
		t.Errorf("unexpected fallback name %q", fb)
	}
}
