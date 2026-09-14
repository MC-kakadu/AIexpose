package checks

import (
	"strings"
	"testing"
)

// A finding headed "2 API key(s)" with one copyable command reads as the whole
// fix. A reader who runs it has secured half of what was found, and nothing
// tells them so.
func TestFixNamesEveryFileWhenKeysSpanSeveral(t *testing.T) {
	hits := []hit{
		{vendor: "GitHub", file: `C:\Users\A\Notes\one.md`, line: 12, masked: "ghp_x"},
		{vendor: "Hugging Face", file: `C:\Users\A\Notes\two.md`, line: 1, masked: "hf_x"},
	}
	note := remainingFilesNote(hits)
	if note == "" {
		t.Fatal("keys in two files produced no note about the second one")
	}
	if !strings.Contains(note, "two.md") {
		t.Error("the second file is never named, so the reader cannot act on it")
	}
	// The one-line copyable command still names the first file, and the note
	// must not repeat it as though it were outstanding.
	cmd := restrictCommand(hits)
	if !strings.Contains(cmd, "one.md") {
		t.Errorf("the copyable command does not name the first file: %q", cmd)
	}
	if strings.Contains(note, "one.md") {
		t.Error("the note repeats the file the command already covers")
	}
}

// One file, one command: adding a paragraph there would be noise.
func TestFixStaysQuietWhenOneFileHoldsEveryKey(t *testing.T) {
	hits := []hit{
		{vendor: "GitHub", file: "/home/a/.env", line: 1, masked: "ghp_x"},
		{vendor: "OpenAI", file: "/home/a/.env", line: 4, masked: "sk_x"},
	}
	if note := remainingFilesNote(hits); note != "" {
		t.Errorf("two keys in one file produced a redundant note: %q", note)
	}
	if note := remainingFilesNote(nil); note != "" {
		t.Errorf("no hits produced a note: %q", note)
	}
}

func TestDistinctFilesKeepsFirstSeenOrder(t *testing.T) {
	hits := []hit{
		{file: "b"}, {file: "a"}, {file: "b"}, {file: "c"},
	}
	got := distinctFiles(hits)
	want := []string{"b", "a", "c"}
	if len(got) != len(want) {
		t.Fatalf("distinctFiles = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("distinctFiles = %v, want %v", got, want)
		}
	}
}
