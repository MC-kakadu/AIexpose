package main

import (
	"bytes"
	"strings"
	"testing"
)

// Reading someone's documents happens only if they say so. Anything that is
// not a clear yes -- silence, a closed pipe, Enter on its own -- is a no.
func TestScanDocsPromptDefaultsToNo(t *testing.T) {
	for _, answer := range []string{"", "\n", "n\n", "no\n", "  \n", "maybe\n", "yes please\n"} {
		var out bytes.Buffer
		if confirmScanDocs(strings.NewReader(answer), &out) {
			t.Errorf("answer %q was taken as consent", answer)
		}
	}
}

func TestScanDocsPromptAcceptsYes(t *testing.T) {
	for _, answer := range []string{"y\n", "Y\n", "yes\n", "YES\n", " y \n"} {
		var out bytes.Buffer
		if !confirmScanDocs(strings.NewReader(answer), &out) {
			t.Errorf("answer %q was not taken as consent", answer)
		}
	}
}

// The prompt has to say what will be read before it asks. A yes to a question
// that did not name Desktop and Documents is not informed consent.
func TestScanDocsPromptSaysWhatItWillRead(t *testing.T) {
	var out bytes.Buffer
	confirmScanDocs(strings.NewReader("n\n"), &out)
	text := out.String()
	for _, want := range []string{"Desktop", "Documents", "Downloads", "Nothing is uploaded", "masked"} {
		if !strings.Contains(text, want) {
			t.Errorf("the prompt does not mention %q:\n%s", want, text)
		}
	}
	if !strings.Contains(text, "[y/N]") {
		t.Error("the prompt does not show that no is the default")
	}
}
