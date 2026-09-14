// Package report renders a scan result for humans and for machines.
package report

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/MC-kakadu/AIexpose/internal/model"
)

// terminalEvidenceLimit is how many items a terminal shows before deferring to
// the report.
const terminalEvidenceLimit = 8

type palette struct{ reset, bold, dim, red, yellow, blue, green, magenta string }

var color = palette{"\033[0m", "\033[1m", "\033[2m", "\033[31m", "\033[33m", "\033[34m", "\033[32m", "\033[35m"}
var plain = palette{}

// UseColor reports whether ANSI codes should be emitted.
func UseColor(force, disable bool) bool {
	if disable {
		return false
	}
	if force {
		return true
	}
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	st, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

func sevColor(p palette, s model.Severity) string {
	switch s {
	case model.Critical:
		return p.red
	case model.High:
		return p.magenta
	case model.Medium:
		return p.yellow
	case model.Low:
		return p.blue
	default:
		return p.dim
	}
}

// Terminal writes the human-readable report.
func Terminal(w io.Writer, r *model.Report, useColor, verbose bool) {
	p := plain
	if useColor {
		p = color
	}

	fmt.Fprintf(w, "\n%saiexpose%s  %s  %s/%s  %s\n",
		p.bold, p.reset, r.Host, r.OS, r.Arch, r.Started.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(w, "%sEvery check ran locally. Nothing about this machine was sent anywhere.%s\n\n", p.dim, p.reset)

	grade := gradeColor(p, r.Grade)
	suffix := ""
	if r.Incomplete {
		suffix = p.yellow + "   (incomplete: some checks could not run)" + p.reset
	}
	fmt.Fprintf(w, "  %s%s  %d/100%s   exposure grade%s\n\n", grade, r.Grade, r.Score, p.reset, suffix)

	counts := r.Counts()
	fmt.Fprintf(w, "  %s%d critical%s   %s%d high%s   %s%d medium%s   %s%d low%s   %s%d info%s\n\n",
		p.red, counts["CRITICAL"], p.reset,
		p.magenta, counts["HIGH"], p.reset,
		p.yellow, counts["MEDIUM"], p.reset,
		p.blue, counts["LOW"], p.reset,
		p.dim, counts["INFO"], p.reset)

	if len(r.Services) > 0 {
		fmt.Fprintf(w, "%sDiscovered services%s\n", p.bold, p.reset)
		for _, s := range r.Services {
			mark := " "
			switch s.Exposure {
			case model.AllIfaces:
				mark = p.red + "!" + p.reset
			case model.LANBound:
				mark = p.yellow + "~" + p.reset
			default:
				mark = p.green + "." + p.reset
			}
			auth := ""
			if s.NoAuth {
				auth = p.red + "  no-auth" + p.reset
			}
			conf := ""
			if !s.Confirmed {
				conf = p.dim + "  (unconfirmed)" + p.reset
			}
			fmt.Fprintf(w, " %s %-26s %s:%-6d %-16s%s%s\n",
				mark, s.Name, s.Listener.Addr, s.Listener.Port, s.Exposure.String(), auth, conf)
		}
		fmt.Fprintln(w)
	} else {
		fmt.Fprintf(w, "%sNo known AI services are listening on this machine.%s\n\n", p.dim, p.reset)
	}

	// Checks that did not run are printed apart from the ones that did, and
	// after them. The HTML report has separated them since v0.17.1, when a
	// real report listed "shell history was not searched" among the passes;
	// the terminal kept mixing them, so the same false comfort survived for
	// everyone who runs this over SSH or in CI.
	var ran, notRun []model.Finding
	for _, f := range r.Findings {
		if f.NotRun {
			notRun = append(notRun, f)
			continue
		}
		ran = append(ran, f)
	}

	shown := 0
	for _, f := range ran {
		if f.Severity == model.Info && !verbose {
			continue
		}
		shown++
		fmt.Fprintf(w, "%s%s%s  %s%s%s\n", sevColor(p, f.Severity), pad(f.SevLabel), p.reset, p.bold, f.Title, p.reset)
		for _, line := range wrap(f.Detail, 84) {
			fmt.Fprintf(w, "          %s\n", line)
		}
		// A terminal cannot fold a long list away, so it shows a sample and
		// points at the report that lists every item.
		for i, e := range f.Evidence {
			if i >= terminalEvidenceLimit {
				fmt.Fprintf(w, "          %s... and %d more (the HTML report lists them all)%s\n",
					p.dim, len(f.Evidence)-i, p.reset)
				break
			}
			for j, line := range strings.Split(e, "\n") {
				prefix := "            "
				if j == 0 {
					prefix = "          - "
				}
				fmt.Fprintf(w, "%s%s%s%s\n", p.dim, prefix, line, p.reset)
			}
		}
		if f.Fix != "" {
			for i, line := range wrap(f.Fix, 84) {
				prefix := "   fix -> "
				if i > 0 {
					prefix = "          "
				}
				fmt.Fprintf(w, "%s%s%s%s\n", p.green, prefix, line, p.reset)
			}
		}
		if f.Command != "" {
			fmt.Fprintf(w, "%s   run -> %s%s\n", p.bold, f.Command, p.reset)
		}
		if f.Ref != "" {
			fmt.Fprintf(w, "%s          %s%s\n", p.dim, f.Ref, p.reset)
		}
		if ids := controlIDs(f); ids != "" {
			fmt.Fprintf(w, "%s  maps -> %s%s\n", p.dim, ids, p.reset)
		}
		fmt.Fprintln(w)
	}
	if shown == 0 {
		fmt.Fprintf(w, "%sNothing to fix. Run with --verbose to see the informational checks.%s\n\n", p.green, p.reset)
	}

	if len(notRun) > 0 && verbose {
		fmt.Fprintf(w, "%sChecks that did not run%s\n", p.bold, p.reset)
		fmt.Fprintf(w, "%sNothing below passed or failed, so a clean result above is not a complete one.%s\n\n",
			p.dim, p.reset)
		for _, f := range notRun {
			fmt.Fprintf(w, "%s%s%s  %s%s%s\n", p.dim, pad("NOT RUN"), p.reset, p.bold, f.Title, p.reset)
			for _, line := range wrap(f.Detail, 84) {
				fmt.Fprintf(w, "          %s\n", line)
			}
			// The fix text on a not-run check is a lead-in to the command
			// that enables it, so it reads as one sentence rather than
			// borrowing the "fix ->" marker used for real problems.
			if f.Fix != "" {
				for _, line := range wrap(f.Fix, 84) {
					fmt.Fprintf(w, "%s          %s%s\n", p.green, line, p.reset)
				}
			}
			if f.Command != "" {
				fmt.Fprintf(w, "%s   run -> %s%s\n", p.bold, f.Command, p.reset)
			}
			fmt.Fprintln(w)
		}
	} else if len(notRun) > 0 {
		titles := make([]string, 0, len(notRun))
		for _, f := range notRun {
			titles = append(titles, f.Title)
		}
		fmt.Fprintf(w, "%s%d check(s) did not run, so this is not a complete result. Re-run with --verbose to see which.%s\n\n",
			p.dim, len(notRun), p.reset)
		_ = titles
	}

	for _, n := range r.Notes {
		fmt.Fprintf(w, "%snote: %s%s\n", p.dim, n, p.reset)
	}
	if len(r.Notes) > 0 {
		fmt.Fprintln(w)
	}

	coverageBlock(w, r, p, verbose)

	fmt.Fprintf(w, "%sscanned in %s%s\n\n", p.dim, r.Duration, p.reset)
}

// controlIDs is the compact form of a finding's control references: the
// identifiers only. A terminal line is not the place for full control titles,
// and someone who needs them has the HTML report open beside it.
func controlIDs(f model.Finding) string {
	if len(f.Controls) == 0 {
		return ""
	}
	ids := make([]string, 0, len(f.Controls))
	for _, c := range f.Controls {
		ids = append(ids, c.ID)
	}
	return strings.Join(ids, "  ")
}

// coverageBlock prints what the scan could not look at.
//
// The default view shows only the risks this scan is blind to, because those
// are the ones a reader would otherwise assume were covered. The rows it did
// check are in the report, and in --verbose here.
func coverageBlock(w io.Writer, r *model.Report, p palette, verbose bool) {
	if len(r.Coverage) == 0 {
		return
	}
	var checked, partial, blind int
	for _, c := range r.Coverage {
		switch c.Scope {
		case model.ScopeChecked:
			checked++
		case model.ScopePartial:
			partial++
		default:
			blind++
		}
	}

	fmt.Fprintf(w, "%sRisk coverage%s  OWASP Top 10 for LLM Applications (2025): "+
		"%d checked, %d partly, %d outside what a local scan can see.\n",
		p.bold, p.reset, checked, partial, blind)

	if !verbose {
		var names []string
		for _, c := range r.Coverage {
			if c.Scope == model.ScopeNotChecked {
				names = append(names, c.Control.ID+" "+c.Control.Title)
			}
		}
		if len(names) > 0 {
			fmt.Fprintf(w, "%s  Not examined: %s%s\n", p.dim, strings.Join(names, "; "), p.reset)
		}
		fmt.Fprintf(w, "%s  The full table, with what each row does and does not cover, is in the HTML report.%s\n\n",
			p.dim, p.reset)
		return
	}

	fmt.Fprintln(w)
	for _, c := range r.Coverage {
		fmt.Fprintf(w, "  %s%-11s%s %s%s%s  %s\n", p.bold, c.Control.ID, p.reset,
			sevColor(p, c.Severity), covVerdict(c), p.reset, c.Control.Title)
		for _, line := range wrap(c.Note, 76) {
			fmt.Fprintf(w, "%s              %s%s\n", p.dim, line, p.reset)
		}
		if len(c.Findings) > 0 {
			fmt.Fprintf(w, "%s              evidence: %s%s\n", p.dim, strings.Join(c.Findings, ", "), p.reset)
		}
	}
	fmt.Fprintln(w)
}

func covVerdict(c model.ControlCoverage) string {
	switch {
	case len(c.Findings) > 0:
		return "[findings ]"
	case c.Scope == model.ScopeChecked:
		return "[clear    ]"
	case c.Scope == model.ScopePartial:
		return "[partial  ]"
	}
	return "[not check]"
}

func gradeColor(p palette, g string) string {
	switch g {
	case "A":
		return p.bold + p.green
	case "B":
		return p.bold + p.blue
	case "C":
		return p.bold + p.yellow
	default:
		return p.bold + p.red
	}
}

func pad(s string) string {
	if len(s) >= 8 {
		return s
	}
	return s + strings.Repeat(" ", 8-len(s))
}

// wrap breaks text into lines of at most n runes, honouring existing newlines.
func wrap(s string, n int) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		para = strings.TrimRight(para, " ")
		if para == "" {
			continue
		}
		indent := ""
		if strings.HasPrefix(para, "  ") {
			indent = "  "
			out = append(out, para)
			continue
		}
		words := strings.Fields(para)
		line := indent
		for _, wd := range words {
			if len(line)+len(wd)+1 > n && strings.TrimSpace(line) != "" {
				out = append(out, line)
				line = indent
			}
			if strings.TrimSpace(line) == "" {
				line += wd
			} else {
				line += " " + wd
			}
		}
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}
