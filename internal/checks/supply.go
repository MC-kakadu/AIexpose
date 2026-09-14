package checks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/MC-kakadu/AIexpose/internal/feed"
	"github.com/MC-kakadu/AIexpose/internal/model"
	"github.com/MC-kakadu/AIexpose/internal/supply"
)

// SupplyOptions controls how drift detection behaves.
type SupplyOptions struct {
	BaselinePath string
	SaveBaseline bool   // accept the current state as the new baseline
	FeedPath     string // an explicit signed feed file, instead of the cache
	DisableFeed  bool

	// Weights is the model-file list the format check already walked. Passing
	// it in keeps the malware hash check from walking gigabytes a second time.
	Weights ModelInventory

	// HashAll lifts the size cap on model files. It is opt-in because reading
	// every weight file costs seconds per gigabyte, and a general malware
	// corpus does not contain model weights.
	HashAll bool

	// HashDBPath overrides where the local malware hash index is read from.
	HashDBPath    string
	DisableHashDB bool
}

// SupplyResult is what the caller needs to act on a drift report without
// scanning the machine again.
type SupplyResult struct {
	Inventory    supply.Inventory
	BaselinePath string
	// Pending lists the components that differ from the accepted baseline, in
	// the words the user just read in the report.
	Pending []string

	// HashIndex describes the malware corpus this scan matched against, for
	// the report's attestation block. Empty when none was used.
	HashIndex string
}

// HasPending reports whether anything is waiting to be reviewed.
func (s SupplyResult) HasPending() bool { return len(s.Pending) > 0 }

// SupplyChain inventories the parts of the local AI stack that execute code,
// flags dangerous behaviour inside them, and compares the result against the
// state the user last accepted.
//
// The point-in-time verdict is the weak part of any scanner: postmark-mcp was
// a well-behaved package for months before it was backdoored. Comparing against
// an accepted baseline is what turns a one-off opinion into ongoing coverage.
func SupplyChain(r *model.Report, opt SupplyOptions) SupplyResult {
	// The index is opened first because its presence is what decides whether
	// the inventory pays to hash binaries. With no index there is nothing to
	// compare against, so nothing extra is read.
	idx := openMalwareIndex(opt.HashDBPath, opt.DisableHashDB)
	defer idx.close()

	inv := supply.TakeWith(supply.Options{MD5: idx.available()})
	res := SupplyResult{Inventory: inv, BaselinePath: opt.BaselinePath}
	for _, s := range inv.Skipped {
		r.Note("Supply chain inventory: " + s)
	}

	res.HashIndex = idx.label()
	reportMalwareHashes(r, inv, opt.Weights, idx, opt.DisableHashDB, opt.HashAll)
	reportTampering(r, inv)
	reportIndicators(r, inv)
	reportUnpinned(r, inv)
	reportUnofficialModels(r, inv)
	if !opt.DisableFeed {
		reportKnownBad(r, inv, opt.FeedPath)
	} else {
		r.Note("Known-bad component list skipped (--no-feed).")
	}

	baseline, err := supply.LoadBaseline(opt.BaselinePath)
	switch {
	case errors.Is(err, supply.ErrNoBaseline):
		if err := supply.SaveBaseline(opt.BaselinePath, inv); err != nil {
			r.Note("Baseline could not be written: " + err.Error())
			return res
		}
		r.Add(model.Finding{
			ID:       "SUP-000",
			Title:    fmt.Sprintf("Baseline recorded for %d installed component(s)", len(inv.Artifacts)),
			Severity: model.Info,
			Detail: "This is the first run, so the current state of your Ollama models, ComfyUI custom nodes, MCP servers and agent skills has been accepted as the baseline. From the next run onwards, any of them that changes will be reported.\n" +
				summarise(inv) + "Baseline file: " + opt.BaselinePath + searchedNote(inv),
		})
		return res
	case err != nil:
		r.Note("Baseline could not be read: " + err.Error())
		return res
	}

	changes := supply.Diff(baseline, inv)
	reportChanges(r, changes, baseline, inv)
	for _, c := range changes {
		res.Pending = append(res.Pending, string(c.Type)+": "+changeLabel(c))
	}

	if opt.SaveBaseline {
		if err := supply.SaveBaseline(opt.BaselinePath, inv); err != nil {
			r.Note("Baseline could not be updated: " + err.Error())
		} else {
			r.Note(fmt.Sprintf("Baseline updated: %d component(s) accepted as the new known-good state.", len(inv.Artifacts)))
			res.Pending = nil
		}
	}
	return res
}

// SupplyChainInventory re-takes the inventory for a caller that needs the
// component list after a scan. It exists for the determinism test, which has to
// build the report exactly the way main does.
func SupplyChainInventory(r *model.Report, baselinePath string) supply.Inventory {
	return supply.Take()
}

// reportKnownBad matches what is installed against the signed list of
// components already known to be malicious. Pattern matching sees behaviour
// that is visible in source and loses to obfuscation; this catches the specific
// published thing regardless of how well it is hidden.
func reportKnownBad(r *model.Report, inv supply.Inventory, feedPath string) {
	f, err := feed.Load(feedPath)
	if err != nil {
		r.Note("Known-bad component list could not be loaded: " + err.Error())
		return
	}

	components := make([]feed.Component, 0, len(inv.Artifacts))
	for _, a := range inv.Artifacts {
		components = append(components, feed.Component{
			ID: a.ID, Kind: a.Kind, Name: a.Name, Path: a.Path,
			Digest: a.Digest, FileDigests: a.FileDigests,
			Package: a.Detail["package"], Version: a.Detail["package_version"],
		})
	}
	reportFeedHits(r, f, components)
}

// reportFeedHits turns list matches into findings. It is separate from loading
// so it can be tested against a feed built in the test rather than one that has
// to be signed first -- the signing key is not in this repository, and a check
// that could only be exercised with it would not be exercised at all.
func reportFeedHits(r *model.Report, f feed.Feed, components []feed.Component) {
	// A feed whose entries cannot do what their author intended is a silent
	// failure: a mistyped version never matches, a version constraint on the
	// wrong kind is thrown away and the entry then matches everything. Neither
	// produces an error during a scan, only a confident wrong answer, so the
	// report says the list is not sound rather than quoting results from it as
	// though they were.
	if probs := f.Validate(); len(probs) > 0 {
		ev := make([]string, 0, len(probs))
		for _, p := range probs {
			ev = append(ev, p.Error())
		}
		r.Add(model.Finding{
			ID:       "SUP-033",
			Title:    fmt.Sprintf("The known-bad list has %d entry problem(s)", len(probs)),
			Severity: model.Low,
			Advisory: true,
			Detail: "Some entries on the list cannot match what they were written to match, so this " +
				"check did not cover everything it appears to. An entry with a mistyped version matches " +
				"nothing; an entry carrying version constraints its kind cannot compare matches every " +
				"install instead of the affected ones.\n" +
				"List version " + f.Version + ", " + f.Origin + ".",
			Evidence: ev,
			Fix:      "Refresh the list, or report this to whoever publishes it:",
			Command:  selfCommand("--update-feed"),
		})
	}

	hits := f.Match(components)
	var confirmed int
	for _, h := range hits {
		detail := h.Entry.Detail
		if detail != "" {
			detail += "\n"
		}
		detail += "Matched because " + h.Why + ".\nPath: " + h.Component.Path +
			"\nList entry: " + h.Entry.ID + " (" + f.Version + ")"

		// A name match whose version could not be compared is not an
		// accusation. Reporting it at the entry's own severity would state as
		// fact the half that was never established.
		if h.Unresolved {
			r.Add(model.Finding{
				ID:       "SUP-034",
				Title:    "Cannot tell whether " + h.Component.Name + " is an affected version",
				Severity: model.Medium,
				Detail: detail + "\n\nThis is not a finding that the component is malicious, and not one " +
					"that it is safe. The published advisory names specific versions; the version this " +
					"install reports is not in a form that can be compared against them, so the question " +
					"is open and a person has to close it.",
				Artifacts: []string{h.Component.ID},
				Fix: "Check the installed version against the advisory yourself. If it is affected, remove " +
					"the component and rotate every credential that was reachable from this machine.",
				Ref: h.Entry.Ref,
			})
			continue
		}

		confirmed++
		r.Add(model.Finding{
			ID:        "SUP-030",
			Title:     h.Entry.Title,
			Severity:  h.Entry.SeverityLevel(),
			Detail:    detail,
			Artifacts: []string{h.Component.ID},
			Fix: "Remove this component now and do not restart the tool that loads it until you have. " +
				"Then rotate every credential that was reachable from this machine.",
			Ref: h.Entry.Ref,
		})
	}

	switch {
	case len(f.Entries) == 0:
		// Saying "nothing matched" against an empty list reads as a pass. It
		// is not one; RULE-001 already reports that the rules are missing.
	case f.Stale():
		r.Add(model.Finding{
			ID:       "SUP-031",
			Title:    fmt.Sprintf("The known-bad component list is %d days old", int(f.Age().Hours()/24)),
			Severity: model.Low,
			Detail: "This check is only as current as its list, and new malicious packages appear constantly.\n" +
				"List version " + f.Version + ", " + f.Origin + ".",
			Fix:     "Refresh it so this check is current again:",
			Command: selfCommand("--update-feed"),
		})
	case len(hits) == 0:
		r.Add(model.Finding{
			ID:       "SUP-032",
			Title:    fmt.Sprintf("No installed component appears on the known-bad list (%d entries)", len(f.Entries)),
			Severity: model.Info,
			Detail:   "List version " + f.Version + ", " + f.Origin + ".",
		})
	}
}

// indicatorFix tells the user what to actually do, which differs by kind: a
// node is a directory to delete, a model is a pull to redo.
func indicatorFix(kind, name string) string {
	if kind == "ollama-model" {
		return "Stop using this model. Remove it and pull a clean copy: ollama rm " + name +
			"\nIf it came from somewhere other than the official registry, do not pull it again from there."
	}
	return "Do not run this component again until you have read the flagged lines yourself. " +
		"If you did not write it, remove the directory, then rotate any credential that was reachable " +
		"from this machine: browser-saved passwords, API keys, and wallet seeds."
}

// indicatorVerb keeps the headline accurate for what was actually inspected.
func indicatorVerb(kind string) string {
	if kind == "ollama-model" {
		return "is instructed to steal or exfiltrate data"
	}
	return "contains code that steals or exfiltrates data"
}

// indicatorPreamble explains the finding in terms of the thing it was found in.
// A system prompt telling a model to post conversations somewhere is a
// different sentence from a node reading a browser password store.
func indicatorPreamble(kind string) string {
	if kind == "ollama-model" {
		return "A model's system prompt or template is an instruction it follows on every request, " +
			"and this one carries directions no legitimate model needs: sending data somewhere, or " +
			"reaching for credentials. A model with a prompt like this turns every conversation you " +
			"have with it into an exfiltration channel."
	}
	return "A component installed in your AI stack contains behaviour that no workflow node or " +
		"agent skill has a legitimate reason to perform. This is the pattern behind the malicious " +
		"ComfyUI node that harvested browser passwords and crypto wallets from everyone who installed it."
}

// reportTampering flags a content-addressed blob whose contents no longer hash
// to its own name. Ollama names every blob after the hash of what is inside it,
// so this needs no threat list to detect and has no innocent explanation: the
// file was changed after it was downloaded.
func reportTampering(r *model.Report, inv supply.Inventory) {
	for _, a := range inv.Artifacts {
		t := a.Detail["tampered"]
		if t == "" {
			continue
		}
		r.Add(model.Finding{
			ID:        "SUP-040",
			Title:     fmt.Sprintf("%s %q has been modified since it was downloaded", kindLabel(a.Kind), a.Name),
			Severity:  model.Critical,
			Artifacts: []string{a.ID},
			Detail: "Ollama stores each part of a model in a file named after the hash of its own contents. " +
				"These no longer match, which means the file was edited after it arrived. The parts affected are the " +
				"ones that steer the model's behaviour, so a change here can make a model follow instructions you never gave it.\n" +
				"Affected: " + t + "\nPath: " + a.Path,
			Fix: "Remove the model and pull it again: ollama rm " + a.Name + " && ollama pull " + a.Name +
				"\nIf you did not edit it yourself, treat anything that model had access to as untrusted.",
		})
	}
}

func reportIndicators(r *model.Report, inv supply.Inventory) {
	for _, a := range inv.Artifacts {
		if len(a.Indicators) == 0 {
			continue
		}
		worst := model.Info
		var lines []string
		seen := map[string]bool{}
		for _, ind := range a.Indicators {
			if ind.Severity > worst {
				worst = ind.Severity
			}
			key := ind.ID + ind.File
			if seen[key] {
				continue
			}
			seen[key] = true
			lines = append(lines, fmt.Sprintf("[%s] %s\n%s:%d\n%s",
				ind.ID, ind.Title, ind.File, ind.Line, ind.Excerpt))
		}
		sort.Strings(lines)
		r.Add(model.Finding{
			ID:        "SUP-001",
			Title:     fmt.Sprintf("%s %q %s", kindLabel(a.Kind), a.Name, indicatorVerb(a.Kind)),
			Severity:  worst,
			Artifacts: []string{a.ID},
			Detail:    indicatorPreamble(a.Kind) + "\nPath: " + a.Path,
			Evidence:  lines,
			Fix:       "Do not run this component again until you have read the flagged lines yourself. If you did not write it, remove the directory, then rotate any credential that was reachable from this machine: browser-saved passwords, API keys, and wallet seeds.",
		})
	}
}

// reportUnofficialModels notes models pulled from somewhere other than the
// official registry. It is not a problem in itself -- plenty of good models are
// hosted elsewhere -- but it is worth knowing which ones they are.
func reportUnofficialModels(r *model.Report, inv supply.Inventory) {
	var lines []string
	for _, a := range inv.Artifacts {
		if reg := a.Detail["unofficial_registry"]; reg != "" {
			lines = append(lines, a.Name+"  (from "+reg+")")
		}
	}
	if len(lines) == 0 {
		return
	}
	sort.Strings(lines)
	r.Add(model.Finding{
		ID:       "SUP-041",
		Title:    fmt.Sprintf("%d model(s) came from a registry other than the official one", len(lines)),
		Severity: model.Low,
		Detail: "These were pulled from a host you chose rather than registry.ollama.ai. That is not wrong, " +
			"but the official registry is the only source whose contents anyone else is watching, so a model from " +
			"elsewhere is one you are vouching for yourself.",
		Evidence: lines,
		Fix:      "Confirm you know who publishes each of these. Their system prompts are inspected by this scan; their weights are not.",
	})
}

func reportUnpinned(r *model.Report, inv supply.Inventory) {
	var lines, ids []string
	for _, a := range inv.Artifacts {
		if pkg := a.Detail["unpinned"]; pkg != "" {
			lines = append(lines, fmt.Sprintf("%s -> %s  (%s)", a.Name, pkg, a.Detail["config"]))
			ids = append(ids, a.ID)
		}
	}
	if len(lines) == 0 {
		return
	}
	sort.Strings(lines)
	r.Add(model.Finding{
		ID:        "SUP-020",
		Title:     fmt.Sprintf("%d MCP server(s) run an unpinned package", len(lines)),
		Severity:  model.Medium,
		Artifacts: ids,
		Detail:    "These servers fetch and execute whatever the registry serves at launch time, so the code you reviewed is not necessarily the code that runs tomorrow. A package that is well-behaved for months and then backdoored reaches you automatically.",
		Evidence:  lines,
		Fix:       "Pin an exact version in the launch arguments (for example my-mcp-server@1.4.2 rather than @latest), and re-review before you move the pin.",
	})
}

// changeLabel names a changed component the way a person would say it, rather
// than with the internal kind slug.
// selfCommand builds a runnable line using the name this executable was
// actually invoked as. A report that tells someone to run "aiexpose" when the
// file on their disk is aiexpose_0.17.1_windows_amd64.exe has handed them a
// command that fails.
func selfCommand(args string) string {
	name := "aiexpose"
	if exe, err := os.Executable(); err == nil {
		name = filepath.Base(exe)
		switch runtime.GOOS {
		case "windows":
			name = ".\\" + name
		default:
			name = "./" + name
		}
	}
	return name + " " + args
}

// acceptCommand is the exact line that records the current state as reviewed.
func acceptCommand() string { return selfCommand("--accept") }

func changeLabel(c supply.Change) string {
	a := c.Current
	if a == nil {
		a = c.Previous
	}
	if a == nil {
		return "unknown component"
	}
	return fmt.Sprintf("%s %q", kindLabel(a.Kind), a.Name)
}

func reportChanges(r *model.Report, changes []supply.Change, baseline, inv supply.Inventory) {
	if len(changes) == 0 {
		title := fmt.Sprintf("All %d installed component(s) match the accepted baseline", len(inv.Artifacts))
		if len(inv.Artifacts) == 0 {
			title = "No AI components are installed to track"
		}
		r.Add(model.Finding{
			ID:       "SUP-002",
			Title:    title,
			Severity: model.Info,
			Detail:   summarise(inv) + "Baseline taken " + baseline.Taken.Format("2006-01-02 15:04 MST") + "." + searchedNote(inv),
		})
		return
	}

	var added, removed, addedIDs []string
	for _, c := range changes {
		switch {
		case c.Type == supply.Modified && c.HasNewIndicator():
			r.Add(model.Finding{
				ID:        "SUP-010",
				Title:     fmt.Sprintf("%s changed and now contains dangerous code", changeLabel(c)),
				Severity:  model.Critical,
				Artifacts: []string{c.Current.ID},
				Detail: "A component that was already installed and accepted has been modified, and the new version contains behaviour that was not there before. This is what a supply chain rug-pull looks like from the inside: you reviewed a safe version, and something else arrived later.\n  " +
					strings.Join(c.What, "\n  ") + "\nPath: " + c.Current.Path,
				Fix: "Treat this machine as compromised until proven otherwise. Stop the tool that loads this component, read the changed files, and rotate credentials that were reachable from here.",
			})
		case c.Type == supply.Modified:
			r.Add(model.Finding{
				ID:        "SUP-011",
				Title:     fmt.Sprintf("%s changed since you accepted it", changeLabel(c)),
				Severity:  model.High,
				Artifacts: []string{c.Current.ID},
				Detail: "This component is not the version you accepted. The change may be a routine update, but nothing verified that, and an update is how malicious code reaches an already-trusted package.\n  " +
					strings.Join(c.What, "\n  ") + "\nPath: " + c.Current.Path,
				Fix:     "Check the upstream changelog or git log for this component. Once you are satisfied, record the new version as known-good.",
				Command: acceptCommand(),
			})
		case c.Type == supply.Added:
			added = append(added, changeLabel(c)+"  ("+c.Current.Path+")")
			addedIDs = append(addedIDs, c.Current.ID)
		default:
			removed = append(removed, changeLabel(c))
		}
	}

	if len(added) > 0 {
		sort.Strings(added)
		r.Add(model.Finding{
			ID:        "SUP-012",
			Title:     fmt.Sprintf("%d new component(s) installed since the baseline", len(added)),
			Severity:  model.Low,
			Artifacts: addedIDs,
			Detail: "These were not present when you last accepted the state of this machine. " +
				"Installing something is usually a thing you did on purpose, so this is a review item rather " +
				"than a warning -- what it protects against is the one you did not do.",
			Evidence: added,
			Fix:      "Confirm you installed each of these on purpose, then record them as reviewed.",
			Command:  acceptCommand(),
		})
	}
	if len(removed) > 0 {
		sort.Strings(removed)
		r.Add(model.Finding{
			ID:       "SUP-013",
			Title:    fmt.Sprintf("%d component(s) removed since the baseline", len(removed)),
			Severity: model.Info,
			Evidence: removed,
		})
	}
}

// searchedNote lists the directories the inventory actually looked in.
//
// A component outside them is invisible, and an invisible component reads as
// an absent one. A machine with ComfyUI Desktop installed reported zero nodes
// for exactly this reason, and nothing in the report said where it had looked.
func searchedNote(inv supply.Inventory) string {
	if len(inv.Roots) == 0 {
		return "\nNo ComfyUI, MCP or agent-skill directory was found in any known location, so none was searched. " +
			"If you have one somewhere else, point at it with the COMFYUI_PATH environment variable; components " +
			"outside the places this scan looks are not covered by it."
	}
	return "\nSearched:\n  " + strings.Join(inv.Roots, "\n  ")
}

func summarise(inv supply.Inventory) string {
	counts := map[string]int{}
	for _, a := range inv.Artifacts {
		counts[a.Kind]++
	}
	if len(counts) == 0 {
		return "No Ollama models, ComfyUI custom nodes, MCP servers or agent skills were found on this machine.\n"
	}
	kinds := make([]string, 0, len(counts))
	for k := range counts {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	parts := make([]string, 0, len(kinds))
	for _, k := range kinds {
		parts = append(parts, fmt.Sprintf("%d %s", counts[k], kindLabel(k)+plural(counts[k])))
	}
	return "Tracking " + strings.Join(parts, ", ") + ".\n"
}

func kindLabel(kind string) string {
	switch kind {
	case "comfy-node":
		return "ComfyUI custom node"
	case "mcp-server":
		return "MCP server"
	case "agent-skill":
		return "agent skill"
	case "ollama-model":
		return "Ollama model"
	}
	return kind
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
