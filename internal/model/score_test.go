package model

import "testing"

// The exposure grade answers "how exposed is this machine". A check that could
// not run is not an answer to that question, so it must not lower the grade --
// but it must mark the report incomplete, or a good grade reads as full
// coverage when half the checks were skipped.
func TestAdvisoryFindingsDoNotLowerTheGrade(t *testing.T) {
	withAdvisory := &Report{}
	withAdvisory.Add(Finding{Severity: Medium, Title: "rules missing", Advisory: true})
	withAdvisory.Add(Finding{Severity: Low, Title: "firewall off"})
	withAdvisory.Finalize()

	clean := &Report{}
	clean.Add(Finding{Severity: Low, Title: "firewall off"})
	clean.Finalize()

	if withAdvisory.Score != clean.Score {
		t.Errorf("advisory finding changed the score: %d vs %d", withAdvisory.Score, clean.Score)
	}
	if !withAdvisory.Incomplete {
		t.Error("a report with an advisory finding must be marked incomplete")
	}
	if clean.Incomplete {
		t.Error("a report with no advisory findings must not be marked incomplete")
	}
	// It still has to be visible.
	if withAdvisory.Counts()["MEDIUM"] != 1 {
		t.Error("an advisory finding must still be counted and shown")
	}
}
