package report

import (
	"html/template"
	"io"
	"strings"

	"github.com/MC-kakadu/AIexpose/internal/model"
)

// HTML writes a self-contained report page: no external fonts, scripts or
// stylesheets, so it renders identically offline and reveals nothing by
// loading remote resources.
func HTML(w io.Writer, r *model.Report) error {
	return htmlTmpl.Execute(w, r)
}

var htmlTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"lower": strings.ToLower,
	// lines splits a detail into paragraphs. Blank ones are dropped: a detail
	// built by joining sentences with "\n\n" for the terminal rendered an
	// empty <p></p> in the page, which shows up as a stray gap.
	"lines": func(s string) []string {
		var out []string
		for _, l := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
			if strings.TrimSpace(l) != "" {
				out = append(out, l)
			}
		}
		return out
	},
	"count":          func(r *model.Report, sev string) int { return r.Counts()[sev] },
	"hasPrefixSpace": func(s string) bool { return strings.HasPrefix(s, "  ") },
	"covBadge":       covBadge,
	"verifyCmd":      verifyCmd,
	"noninfo": func(r *model.Report) []model.Finding {
		var out []model.Finding
		for _, f := range r.Findings {
			if f.Severity != model.Info {
				out = append(out, f)
			}
		}
		return out
	},
	"info": func(r *model.Report) []model.Finding {
		var out []model.Finding
		for _, f := range r.Findings {
			if f.Severity == model.Info && !f.NotRun {
				out = append(out, f)
			}
		}
		return out
	},
	// notrun are checks that did not happen. Listing them beside the ones that
	// passed would let a reader count them as coverage.
	"notrun": func(r *model.Report) []model.Finding {
		var out []model.Finding
		for _, f := range r.Findings {
			if f.NotRun {
				out = append(out, f)
			}
		}
		return out
	},
}).Parse(htmlSource))

// verifyCmd names the executable the reader actually ran. Printing a generic
// "aiexpose" when the file on their disk is aiexpose_0.17.0_windows_amd64.exe
// gives them a command that does not work.
func verifyCmd(r *model.Report) string {
	name := r.Tool
	if p := r.Attest.ExePath; p != "" {
		name = p[strings.LastIndexAny(p, `/\`)+1:]
		if r.OS == "windows" {
			name = ".\\" + name
		} else {
			name = "./" + name
		}
	}
	return name + " --verify SHA256SUMS"
}

// covBadge turns one coverage row into its verdict chip. The four states are
// deliberately distinct: "no evidence found" is a result, "not checked" is not,
// and a report that rendered them the same way would be lying by layout.
func covBadge(c model.ControlCoverage) template.HTML {
	class, label := "sc-none", "not checked"
	switch {
	case len(c.Findings) > 0:
		// The severity alone. The finding IDs are listed in the row beside it,
		// so a count here would only repeat what the reader can see.
		class, label = "sc-found", strings.ToLower(c.SevLabel)
	case c.Scope == model.ScopeChecked:
		class, label = "sc-clear", "no evidence found"
	case c.Scope == model.ScopePartial:
		class, label = "sc-partial", "partly checked"
	}
	return template.HTML(`<span class="sc ` + class + `">` + label + `</span>`)
}

const htmlSource = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>aiexpose report - {{.Host}}</title>
<style>
:root{
  --bg:#f6f7f9; --card:#fff; --fg:#15181d; --muted:#5b626e; --line:#e3e6ea;
  --crit:#c0233b; --high:#b53fa8; --med:#a2701a; --low:#2264c4; --info:#6b7280; --ok:#177a4a;
}
@media (prefers-color-scheme:dark){:root{
  --bg:#0f1216; --card:#171b21; --fg:#e8eaed; --muted:#9aa3af; --line:#252b33;
  --crit:#ff6b7f; --high:#e08ad8; --med:#e3b45c; --low:#79aaf5; --info:#8b95a3; --ok:#57cf95;
}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
  font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
.wrap{max-width:860px;margin:0 auto;padding:32px 20px 64px}
header{display:flex;align-items:center;gap:20px;flex-wrap:wrap;margin-bottom:8px}
.grade{width:88px;height:88px;border-radius:50%;display:flex;flex-direction:column;
  align-items:center;justify-content:center;font-weight:700;flex:none;color:#fff}
.grade b{font-size:30px;line-height:1}
.grade span{font-size:11px;font-weight:600;opacity:.9}
.g-A{background:var(--ok)}.g-B{background:var(--low)}.g-C{background:var(--med)}
.g-D{background:var(--high)}.g-F{background:var(--crit)}
h1{font-size:20px;margin:0 0 4px}
.meta{color:var(--muted);font-size:13px;margin:0}
.privacy{margin:18px 0 26px;padding:10px 14px;border-left:3px solid var(--ok);
  background:var(--card);border-radius:0 8px 8px 0;color:var(--muted);font-size:13px}
.tally{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 26px}
.pill{padding:4px 11px;border-radius:999px;font-size:12px;font-weight:600;
  border:1px solid var(--line);background:var(--card)}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);
  margin:32px 0 12px;font-weight:700}
table{width:100%;border-collapse:collapse;background:var(--card);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:9px 13px;border-bottom:1px solid var(--line);font-size:13px}
th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.05em}
tr:last-child td{border-bottom:none}
.tag{font-size:11px;padding:2px 7px;border-radius:5px;font-weight:600;white-space:nowrap}
.t-all{background:var(--crit);color:#fff}.t-lan{background:var(--med);color:#fff}
.t-loop{background:var(--ok);color:#fff}.t-noauth{background:var(--crit);color:#fff;margin-left:6px}
.f{background:var(--card);border:1px solid var(--line);border-left-width:4px;
  border-radius:10px;padding:15px 18px;margin-bottom:12px}
.f-CRITICAL{border-left-color:var(--crit)}.f-HIGH{border-left-color:var(--high)}
.f-MEDIUM{border-left-color:var(--med)}.f-LOW{border-left-color:var(--low)}
.f-INFO{border-left-color:var(--info)}
.f h3{margin:0 0 6px;font-size:15px;display:flex;gap:9px;align-items:baseline;flex-wrap:wrap}
.sev{font-size:10px;font-weight:700;letter-spacing:.07em;padding:2px 7px;border-radius:4px;color:#fff}
.s-CRITICAL{background:var(--crit)}.s-HIGH{background:var(--high)}.s-MEDIUM{background:var(--med)}
.s-LOW{background:var(--low)}.s-INFO{background:var(--info)}
.f p{margin:6px 0;font-size:14px}
.f .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;
  color:var(--muted);white-space:pre-wrap;word-break:break-all}
.fix{margin-top:9px;padding-top:9px;border-top:1px dashed var(--line);color:var(--ok);font-size:13.5px}
.fix b{font-weight:700}
a{color:var(--low)}
footer{margin-top:40px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:16px}
.note{color:var(--muted);font-size:13px;margin:4px 0}
details.ev{margin:10px 0 2px}
details.ev>summary{cursor:pointer;list-style:none;display:inline-flex;align-items:center;gap:7px;
  font-size:12.5px;font-weight:600;color:var(--muted);background:var(--bg);
  border:1px solid var(--line);border-radius:7px;padding:5px 11px;user-select:none}
details.ev>summary::-webkit-details-marker{display:none}
details.ev>summary::before{content:"";width:0;height:0;flex:none;
  border-left:5px solid currentColor;border-top:4px solid transparent;border-bottom:4px solid transparent;
  transition:transform .15s ease}
details.ev[open]>summary::before{transform:rotate(90deg)}
details.ev>summary:hover{color:var(--fg);border-color:var(--muted)}
.evlist{margin-top:10px;border-left:2px solid var(--line);padding-left:12px}
.evlist p{margin:5px 0}
@media print{details.ev>summary{display:none}details.ev>.evlist{display:block}}
.cmd{margin-top:10px;display:flex;align-items:center;gap:9px;flex-wrap:wrap}
.cmd code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;
  background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:5px 10px;color:var(--fg)}
.cmd button{font:inherit;font-size:12.5px;font-weight:600;cursor:pointer;
  color:var(--card);background:var(--ok);border:0;border-radius:6px;padding:6px 13px}
.cmd button:hover{filter:brightness(1.08)}
.cmd button[data-done]{background:var(--muted)}
.cmd .hint{font-size:12px;color:var(--muted)}
@media print{.cmd button{display:none}}
.warn{font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;
  background:var(--med);color:#fff;padding:2px 8px;border-radius:5px;vertical-align:middle}
@media (max-width:520px){.grade{width:68px;height:68px}.grade b{font-size:24px}}

/* Control references on a finding. Small, because they are for the reader who
   has to file this somewhere, not for the reader deciding what to do next. */
.ctrls{margin-top:10px;display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.ctrls .lbl{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;font-weight:700}
.ctrl{font-size:11.5px;font-weight:600;text-decoration:none;color:var(--muted);
  border:1px solid var(--line);background:var(--bg);border-radius:5px;padding:2px 8px;white-space:nowrap}
.ctrl:hover{color:var(--fg);border-color:var(--muted)}
.ctrl b{font-weight:700;color:var(--fg)}

/* Coverage table. The three scope colours have to be distinguishable at a
   glance, because the whole point is that "not checked" is not "passed". */
.cov{width:100%;border-collapse:collapse;background:var(--card);border-radius:10px;overflow:hidden}
.cov td{vertical-align:top;padding:11px 13px;border-bottom:1px solid var(--line);font-size:13px}
.cov tr:last-child td{border-bottom:none}
.cov .cid{white-space:nowrap;font-weight:700;width:1%}
.cov .cid a{text-decoration:none;color:inherit}
.cov .cnote{color:var(--muted);font-size:12.5px;margin:5px 0 0}
.cov .cf{margin-top:6px;display:flex;gap:5px;flex-wrap:wrap}
.cov .cf span{font-size:11px;font-weight:600;padding:1px 6px;border-radius:4px;
  border:1px solid var(--line);background:var(--bg);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.sc{font-size:10px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;
  padding:2px 7px;border-radius:4px;color:#fff;white-space:nowrap;display:inline-block}
.sc-found{background:var(--crit)}
.sc-clear{background:var(--ok)}
.sc-partial{background:var(--med)}
.sc-none{background:var(--info)}
.covlegend{color:var(--muted);font-size:12.5px;margin:10px 0 12px}
.pathcell{color:var(--muted);font-size:11.5px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;word-break:break-all}
.srccell{color:var(--muted);font-size:12px;word-break:break-all;max-width:220px}
.mono2{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11.5px;color:var(--muted)}
tr.flagged td{background:color-mix(in srgb,var(--crit) 7%,transparent)}
/* A component awaiting review is not a component under suspicion. It gets a
   quiet chip and no row tint; only an actual finding colours the row. */
.t-new{background:transparent;color:var(--muted);border:1px solid var(--line);font-weight:600}
/* The severity the finding gave this review item, shown on the chip so the
   table and the finding cannot disagree about how much it matters. */
.sv{font-weight:700;text-transform:uppercase;letter-spacing:.04em}
.sv-LOW{color:var(--low)}.sv-MEDIUM{color:var(--med)}.sv-HIGH{color:var(--high)}
.sv-CRITICAL{color:var(--crit)}.sv-INFO{color:var(--info)}

/* Attestation: a dense key/value block, monospaced where the value is a hash. */
.att{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:4px 18px}
.att dl{display:grid;grid-template-columns:auto 1fr;gap:0 18px;margin:14px 0}
.att dt{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em;
  font-weight:700;padding:3px 0;white-space:nowrap}
.att dd{margin:0;padding:3px 0;font-size:13px;word-break:break-all}
.att dd.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
@media (max-width:560px){.att dl{grid-template-columns:1fr;gap:0}
  .att dt{padding-top:10px}.cov .cid{width:auto}}
</style></head><body><div class="wrap">

<header>
  <div class="grade g-{{.Grade}}"><b>{{.Grade}}</b><span>{{.Score}}/100</span></div>
  <div>
    <h1>Local AI exposure report{{if .Incomplete}} <span class="warn">incomplete</span>{{end}}</h1>
    <p class="meta">{{.Host}} &middot; {{.OS}}/{{.Arch}} &middot; {{.Started.Format "2006-01-02 15:04 MST"}} &middot; {{.Duration}}</p>
  </div>
</header>

{{if .Incomplete}}<p class="privacy" style="border-left-color:var(--med)">Some checks could not run, so the grade below reflects only what was actually examined. The findings marked below say which.</p>{{end}}
<p class="privacy">Every check in this report ran on this machine. No inventory, address, filename or credential was transmitted anywhere, and this page loads no remote resources.</p>

<div class="tally">
  <span class="pill" style="color:var(--crit)">{{count . "CRITICAL"}} critical</span>
  <span class="pill" style="color:var(--high)">{{count . "HIGH"}} high</span>
  <span class="pill" style="color:var(--med)">{{count . "MEDIUM"}} medium</span>
  <span class="pill" style="color:var(--low)">{{count . "LOW"}} low</span>
  <span class="pill" style="color:var(--info)">{{count . "INFO"}} info</span>
</div>

<h2>Discovered services</h2>
{{if not .Services}}
<p class="covlegend">No AI service was listening when this scan ran. That is the result of the
check, not the absence of one &mdash; every port this tool recognises was looked at.{{if .ServiceScopeNote}}
{{.ServiceScopeNote}}{{end}}</p>
{{else}}
<table><thead><tr><th>Service</th><th>Bound to</th><th>Exposure</th><th>Process</th></tr></thead><tbody>
{{range .Services}}<tr>
  <td><b>{{.Name}}</b>{{if not .Confirmed}} <span style="color:var(--muted);font-size:11px">(unconfirmed)</span>{{end}}</td>
  <td class="mono">{{.Listener.Addr}}:{{.Listener.Port}}</td>
  <td>
    {{if eq .ExposureS "all-interfaces"}}<span class="tag t-all">all interfaces</span>
    {{else if eq .ExposureS "lan-bound"}}<span class="tag t-lan">local network</span>
    {{else}}<span class="tag t-loop">loopback</span>{{end}}
    {{if .NoAuth}}<span class="tag t-noauth">no auth</span>{{end}}
  </td>
  <td class="mono">{{if .Listener.Process}}{{.Listener.Process}}{{end}}{{if .Listener.PID}} ({{.Listener.PID}}){{end}}</td>
</tr>{{end}}
</tbody></table>
{{end}}

{{if .Components}}
<h2>AI components installed</h2>
<table>
<tr><th>Type</th><th>Name</th><th>Version</th><th>Source</th><th>Fingerprint</th></tr>
{{range .Components}}
<tr{{if .Flag}} class="flagged"{{end}}>
  <td>{{.Kind}}</td>
  <td><b>{{.Name}}</b>{{if .Flag}} <span class="tag t-all">{{lower .Flag}}</span>{{end}}{{if .State}} <span class="tag t-new">{{if .StateSev}}<b class="sv sv-{{.StateSev}}">{{lower .StateSev}}</b> {{end}}{{.State}}</span>{{end}}<br><span class="pathcell">{{.Path}}</span></td>
  <td>{{if .Version}}{{.Version}}{{else}}&mdash;{{end}}</td>
  <td class="srccell">{{if .Source}}{{.Source}}{{else}}&mdash;{{end}}</td>
  <td class="mono2">{{if .Digest}}{{.Digest}}{{else}}&mdash;{{end}}</td>
</tr>
{{end}}
</table>
<p class="covlegend">The fingerprint is this tool's own SHA-256 over each component's code and
config files, truncated for reading. It is what drift is measured against, not a hash any
registry published. Export the full inventory as CycloneDX with
<code>aiexpose --aibom bom.cdx.json</code>.</p>
{{end}}

{{with noninfo .}}
<h2>Findings</h2>
{{range .}}
<div class="f f-{{.SevLabel}}">
  <h3><span class="sev s-{{.SevLabel}}">{{.SevLabel}}</span> {{.Title}}</h3>
  {{range lines .Detail}}<p{{if hasPrefixSpace .}} class="mono"{{end}}>{{.}}</p>{{end}}
  {{template "evidence" .}}
  {{if .Fix}}<div class="fix"><b>Fix:</b> {{.Fix}}</div>{{end}}
  {{template "controls" .}}
  {{if .Command}}
  <div class="cmd">
    <code>{{.Command}}</code>
    <button type="button" data-copy="{{.Command}}">Copy command</button>
    <span class="hint">Run it in a terminal in the folder holding aiexpose.</span>
  </div>
  {{end}}
  {{if .Ref}}<p><a href="{{.Ref}}" rel="noreferrer noopener">{{.Ref}}</a></p>{{end}}
</div>
{{end}}
{{end}}

{{define "evidence"}}
  {{if .Evidence}}
    {{if gt (len .Evidence) 5}}
<details class="ev">
  <summary>Show all {{len .Evidence}} items</summary>
  <div class="evlist">{{range .Evidence}}<p class="mono">{{.}}</p>{{end}}</div>
</details>
    {{else}}
<div class="evlist">{{range .Evidence}}<p class="mono">{{.}}</p>{{end}}</div>
    {{end}}
  {{end}}
{{end}}

{{if .Coverage}}
<h2>Risk coverage</h2>
<p class="covlegend">Every risk in the OWASP Top 10 for LLM Applications (2025), and what this
scan can honestly say about each one. Half of that list describes how an application behaves
while it runs; a scan of files and sockets cannot see that, and the rows below say so rather
than leaving a blank that reads as a pass.</p>
<table class="cov">
{{range .Coverage}}
<tr>
  <td class="cid"><a href="{{.Control.URL}}" rel="noreferrer noopener">{{.Control.ID}}</a></td>
  <td>
    <b>{{.Control.Title}}</b>
    <p class="cnote">{{.Note}}</p>
    {{if .Findings}}<div class="cf">{{range .Findings}}<span>{{.}}</span>{{end}}</div>{{end}}
  </td>
  <td style="width:1%;text-align:right">{{covBadge .}}</td>
</tr>
{{end}}
</table>
{{end}}

{{with info .}}
<h2>Checks that passed</h2>
{{range .}}
<div class="f f-INFO">
  <h3><span class="sev s-INFO">INFO</span> {{.Title}}</h3>
  {{range lines .Detail}}<p>{{.}}</p>{{end}}
  {{template "evidence" .}}
  {{template "controls" .}}
</div>
{{end}}
{{end}}

{{$nr := notrun .}}
{{if or .Notes $nr}}
<h2>Checks that did not run</h2>
<p class="covlegend">Nothing below passed or failed. These are the parts of the scan that did
not happen, and why &mdash; so a clean report is never mistaken for a complete one.</p>
{{range $nr}}
<div class="f f-INFO">
  <h3><span class="sev s-INFO">NOT RUN</span> {{.Title}}</h3>
  {{range lines .Detail}}<p>{{.}}</p>{{end}}
  {{if .Fix}}<div class="fix"><b>To enable it:</b> {{.Fix}}</div>{{end}}
  {{if .Command}}
  <div class="cmd">
    <code>{{.Command}}</code>
    <button type="button" data-copy="{{.Command}}">Copy command</button>
  </div>
  {{end}}
</div>
{{end}}
{{range .Notes}}<p class="note">{{.}}</p>{{end}}
{{end}}

{{if .Attest.Version}}
<h2>How this report was produced</h2>
<div class="att">
<dl>
  <dt>Scanner</dt><dd>{{.Attest.Tool}} {{.Attest.Version}}{{if .Attest.Profile}} &middot; {{.Attest.Profile}} build{{end}} &middot; {{.OS}}/{{.Arch}}</dd>
  {{if .Attest.SelfDigest}}<dt>Binary SHA-256</dt><dd class="mono">{{.Attest.SelfDigest}}</dd>{{end}}
  {{if .Attest.ExePath}}<dt>Run from</dt><dd class="mono">{{.Attest.ExePath}}</dd>{{end}}
  <dt>Started</dt><dd>{{.Started.Format "2006-01-02 15:04:05 MST"}} &middot; took {{.Duration}}</dd>
  <dt>Detection rules</dt><dd>{{if .Attest.RuleVersion}}version {{.Attest.RuleVersion}} &middot; {{end}}{{.Attest.RuleCounts}}{{if .Attest.RuleOrigin}}<br><span class="mono">{{.Attest.RuleOrigin}}</span>{{end}}</dd>
  {{if .Attest.HashIndex}}<dt>Malware corpus</dt><dd>{{.Attest.HashIndex}}</dd>{{end}}
  <dt>Components</dt><dd>{{.Attest.Components}} inventoried and fingerprinted</dd>
</dl>
</div>
<p class="covlegend">Verify this binary is the one it claims to be:
<code>{{verifyCmd .}}</code>. Findings are only as good as the rule set that made
them, so the version above is part of the result.</p>
{{end}}

{{define "controls"}}{{if .Controls}}
<div class="ctrls"><span class="lbl">Maps to</span>
{{range .Controls}}<a class="ctrl" href="{{.URL}}" rel="noreferrer noopener" title="{{.Framework}}: {{.Title}}"><b>{{.ID}}</b> {{.Title}}</a>{{end}}
</div>
{{end}}{{end}}

<script>
// The only script on this page. It copies text to the clipboard and does
// nothing else: no network, no storage, no reading of the page's contents.
document.addEventListener("click", function (e) {
  var b = e.target.closest ? e.target.closest("[data-copy]") : null;
  if (!b) return;
  var text = b.getAttribute("data-copy");
  var done = function () {
    var was = b.textContent;
    b.textContent = "Copied";
    b.setAttribute("data-done", "1");
    setTimeout(function () { b.textContent = was; b.removeAttribute("data-done"); }, 1600);
  };
  var fallback = function () {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); done(); } catch (err) { /* leave the text on screen */ }
    document.body.removeChild(ta);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done, fallback);
  } else {
    fallback();
  }
});
</script>

<footer>Generated by {{.Tool}} {{.Version}}. This report reflects one moment in time; re-run it after installing new AI tools or extensions.</footer>
</div></body></html>
`
