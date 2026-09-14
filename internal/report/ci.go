package report

import (
	"fmt"
	"io"

	"github.com/MC-kakadu/AIexpose/internal/ci"
	"github.com/MC-kakadu/AIexpose/internal/policy"
)

// CI writes the gate result for a human reading a build log.
func CI(w io.Writer, res ci.Result, useColor bool) {
	p := plain
	if useColor {
		p = color
	}

	errs, warns, waived := res.Counts()
	fmt.Fprintf(w, "\n%saiexpose ci%s  %d component(s) inspected  policy: %s\n",
		p.bold, p.reset, res.Components, res.PolicySource)
	if res.FeedVersion != "" {
		fmt.Fprintf(w, "%sknown-bad list %s%s\n", p.dim, res.FeedVersion, p.reset)
	}
	fmt.Fprintln(w)

	for _, v := range res.Violations {
		label, colour := "warning", p.yellow
		switch {
		case v.Exempted != nil:
			label, colour = "exempt", p.dim
		case v.Level == policy.Error:
			label, colour = "error", p.red
		}
		fmt.Fprintf(w, "%s%-8s%s %s%s%s\n", colour, label, p.reset, p.bold, v.Title, p.reset)
		fmt.Fprintf(w, "         %srule: %s%s\n", p.dim, v.Rule, p.reset)
		if v.Path != "" {
			loc := v.Path
			if v.Line > 0 {
				loc = fmt.Sprintf("%s:%d", v.Path, v.Line)
			}
			fmt.Fprintf(w, "         %s%s%s\n", p.dim, loc, p.reset)
		}
		for _, line := range wrap(v.Detail, 80) {
			fmt.Fprintf(w, "         %s\n", line)
		}
		if v.Exempted != nil {
			fmt.Fprintf(w, "         %sexempted: %s%s\n", p.green, v.Exempted.Reason, p.reset)
			if v.Exempted.Expires != "" {
				fmt.Fprintf(w, "         %sexpires %s%s\n", p.dim, v.Exempted.Expires, p.reset)
			}
		}
		if v.Ref != "" {
			fmt.Fprintf(w, "         %s%s%s\n", p.dim, v.Ref, p.reset)
		}
		fmt.Fprintln(w)
	}

	for _, n := range res.Notes {
		fmt.Fprintf(w, "%snote: %s%s\n", p.dim, n, p.reset)
	}
	if len(res.Notes) > 0 {
		fmt.Fprintln(w)
	}
	if res.LockWritten != "" {
		fmt.Fprintf(w, "%sLockfile written to %s. Commit it.%s\n\n", p.green, res.LockWritten, p.reset)
	}

	switch {
	case errs > 0:
		fmt.Fprintf(w, "%s%d error(s)%s, %d warning(s), %d exempted. Gate failed.\n\n",
			p.red+p.bold, errs, p.reset, warns, waived)
	case warns > 0:
		fmt.Fprintf(w, "%sNo errors%s, %d warning(s), %d exempted. Gate passed.\n\n",
			p.green, p.reset, warns, waived)
	default:
		fmt.Fprintf(w, "%sGate passed.%s %d exempted.\n\n", p.green+p.bold, p.reset, waived)
	}
}
