package main

import "testing"

// A prompt is answerable when a person is at both ends of it. This used to
// also require a Windows double-click, which meant a terminal user was never
// asked whether to search their document folders -- and their report then said
// "no plaintext API keys found" having looked in far fewer places than the
// same tool looked in for somebody who double-clicked it.
func TestPromptingDependsOnAPersonBeingThere(t *testing.T) {
	// --no-pause disables prompts outright, whatever else is true.
	if canPrompt(true, true) {
		t.Error("prompted even though prompting was disabled")
	}

	// In this test binary stdin and stdout are not terminals, so nothing may
	// prompt: a scan in a script or a pipeline that blocks on a question is
	// broken, and that is the case this guard protects.
	if canPrompt(false, false) {
		t.Error("prompted with no terminal attached")
	}
	if canPrompt(true, false) {
		t.Error("--pause forced a prompt with no terminal attached")
	}
}
