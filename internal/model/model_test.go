package model

import "testing"

func TestMaskSecret(t *testing.T) {
	secret := "sk" + "-proj-AbCdEf1234567890QwErTyUiOp"
	got := MaskSecret(secret)
	if got == secret {
		t.Fatal("secret was not masked")
	}
	if len(got) < 10 {
		t.Errorf("mask too short: %q", got)
	}
	if MaskSecret("short") != "*****" {
		t.Errorf("short secrets must be fully masked, got %q", MaskSecret("short"))
	}
}

func TestScoreAndGrade(t *testing.T) {
	cases := []struct {
		sevs      []Severity
		wantScore int
		wantGrade string
	}{
		{nil, 100, "A"},
		{[]Severity{Info, Info}, 100, "A"},
		{[]Severity{Low}, 96, "A"},
		{[]Severity{Medium, Medium}, 80, "B"},
		{[]Severity{High, Medium, Low}, 66, "C"},
		{[]Severity{Critical, High}, 45, "D"},
		{[]Severity{Critical, Critical, High}, 10, "F"},
		{[]Severity{Critical, Critical, Critical, Critical}, 0, "F"},
	}
	for _, c := range cases {
		r := &Report{}
		for _, s := range c.sevs {
			r.Add(Finding{Severity: s, Title: "x"})
		}
		r.Finalize()
		if r.Score != c.wantScore || r.Grade != c.wantGrade {
			t.Errorf("%v -> score %d grade %s; want %d %s",
				c.sevs, r.Score, r.Grade, c.wantScore, c.wantGrade)
		}
	}
}

func TestFinalizeSortsBySeverity(t *testing.T) {
	r := &Report{}
	r.Add(Finding{Severity: Low, Title: "low"})
	r.Add(Finding{Severity: Critical, Title: "crit"})
	r.Add(Finding{Severity: Medium, Title: "med"})
	r.Finalize()
	if r.Findings[0].Title != "crit" || r.Findings[2].Title != "low" {
		t.Errorf("findings not sorted by severity: %+v", r.Findings)
	}
}
