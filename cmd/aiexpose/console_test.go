package main

import (
	"bytes"
	"strings"
	"testing"
)

// Accepting a baseline is the moment the user vouches for what is installed.
// A stray keypress, a piped empty stream or a closed stdin must never be read
// as agreement: everything after it is measured against what is agreed here.
func TestConfirmAcceptDefaultsToNo(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{"explicit y", "y\n", true},
		{"explicit yes", "yes\n", true},
		{"uppercase", "  Y  \n", true},
		{"just enter", "\n", false},
		{"explicit n", "n\n", false},
		{"no", "no\n", false},
		{"anything else", "maybe\n", false},
		{"closed stdin", "", false},
		{"whitespace only", "   \n", false},
		// A trailing newline is not guaranteed when input is piped.
		{"y without newline", "y", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			got := confirmAccept(strings.NewReader(c.input), &out, []string{"added: agent skill \"x\""})
			if got != c.want {
				t.Errorf("confirmAccept(%q) = %v, want %v", c.input, got, c.want)
			}
			if !strings.Contains(out.String(), "[y/N]") {
				t.Error("the prompt must show that no is the default")
			}
			if !strings.Contains(out.String(), `agent skill "x"`) {
				t.Error("the user must see what they are accepting before answering")
			}
		})
	}
}

func TestConfirmAcceptListsALongSetWithoutFlooding(t *testing.T) {
	var pending []string
	for i := 0; i < 40; i++ {
		pending = append(pending, "added: thing")
	}
	var out bytes.Buffer
	confirmAccept(strings.NewReader("n\n"), &out, pending)
	if !strings.Contains(out.String(), "and 28 more") {
		t.Errorf("a long list should be summarised, got:\n%s", out.String())
	}
}

// A redirected run must never stop to ask; a scheduled scan would hang.
func TestCanPromptRefusesWhenNotATerminal(t *testing.T) {
	if canPrompt(true, true) {
		t.Error("--no-pause must suppress the question")
	}
	// stdin here is not a character device under `go test`, so even forcing
	// must not open a prompt nothing can answer.
	if canPrompt(true, false) {
		t.Error("a non-terminal stdin must not be prompted")
	}
}
