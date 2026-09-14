package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/MC-kakadu/AIexpose/internal/advice"
	"github.com/MC-kakadu/AIexpose/internal/model"
)

// Launch scripts are the files people double-click to start ComfyUI or a
// Stable Diffusion web UI, and they are where --listen and --share get pasted
// and forgotten. This check reads them and says what to delete. It does not
// edit them: see internal/advice for why this tool stopped writing to disk.

// launchScriptNames are the files people actually edit to start these tools.
var launchScriptNames = map[string]bool{
	"webui-user.bat": true, "webui-user.sh": true, "webui.sh": true,
	"run_nvidia_gpu.bat": true, "run_cpu.bat": true, "run_nvidia_gpu_fast.bat": true,
	"start.bat": true, "start.sh": true, "run.bat": true, "run.sh": true,
	"launch.bat": true, "launch.sh": true, "comfyui.bat": true,
}

// findLaunchScripts looks in the places these tools install themselves.
func findLaunchScripts(home string) []string {
	roots := []string{
		filepath.Join(home, "ComfyUI"),
		filepath.Join(home, "comfyui"),
		filepath.Join(home, "ComfyUI_windows_portable"),
		filepath.Join(home, "Documents", "ComfyUI_windows_portable"),
		filepath.Join(home, "Documents", "ComfyUI"),
		filepath.Join(home, "stable-diffusion-webui"),
		filepath.Join(home, "sd-webui"),
		filepath.Join(home, "text-generation-webui"),
	}
	var out []string
	seen := map[string]bool{}
	for _, root := range roots {
		if st, err := os.Stat(root); err != nil || !st.IsDir() {
			continue
		}
		// One level deep only: portable builds nest one directory, and a deep
		// walk here would wander into model and venv trees.
		for _, dir := range []string{root, filepath.Join(root, "ComfyUI")} {
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if e.IsDir() || !launchScriptNames[strings.ToLower(e.Name())] {
					continue
				}
				p := filepath.Join(dir, e.Name())
				if !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}
		}
	}
	return out
}

// targetFlags are the launch arguments that move a service off loopback or
// publish it outright.
var targetFlags = map[string]bool{
	"--share": true, "--listen": true, "--host": true, "--server-name": true,
}

// exposedAddrs are the values that mean "every interface". A specific address
// such as --host 192.168.1.5 is a deliberate choice and is left alone.
var exposedAddrs = map[string]bool{"0.0.0.0": true, "::": true, "*": true}

func isDelim(b byte) bool { return b == ' ' || b == '\t' || b == '"' || b == '\'' }

type segment struct {
	start, end int
	isToken    bool
}

// tokenize splits a line into alternating delimiter and token runs. Quotes
// count as delimiters, which is what lets this see the flag in
// COMMANDLINE_ARGS="--listen --share": a regex requiring leading whitespace
// misses it, and RE2 has no lookbehind to express the alternative.
func tokenize(line string) []segment {
	var segs []segment
	for i := 0; i < len(line); {
		j := i
		delim := isDelim(line[i])
		for j < len(line) && isDelim(line[j]) == delim {
			j++
		}
		segs = append(segs, segment{i, j, !delim})
		i = j
	}
	return segs
}

// dropDecision says what to remove for one recognised flag.
func dropDecision(name, value string, hasValue bool) (dropFlag, dropValue bool) {
	switch name {
	case "--share":
		return true, false
	case "--listen":
		// --listen alone already means every interface.
		return true, hasValue && exposedAddrs[value]
	case "--host", "--server-name":
		if hasValue && exposedAddrs[value] {
			return true, true
		}
	}
	return false, false
}

// stripFlags removes network-exposing launch flags from one line, along with
// exactly one run of surrounding whitespace so the result stays tidy.
func stripFlags(line string) string {
	segs := tokenize(line)
	drop := make([]bool, len(segs))

	tokenAt := func(i int) (string, int) {
		for j := i + 1; j < len(segs); j++ {
			if segs[j].isToken {
				return line[segs[j].start:segs[j].end], j
			}
			if !whitespaceOnly(line[segs[j].start:segs[j].end]) {
				return "", -1 // a quote ends the argument run
			}
		}
		return "", -1
	}

	for i, sg := range segs {
		if !sg.isToken || drop[i] {
			continue
		}
		tok := line[sg.start:sg.end]
		name, inlineVal, hasEq := strings.Cut(tok, "=")
		if !targetFlags[name] {
			continue
		}
		if hasEq {
			if f, _ := dropDecision(name, inlineVal, true); f {
				drop[i] = true
			}
			continue
		}
		nextTok, nextIdx := tokenAt(i)
		dropFlag, dropVal := dropDecision(name, nextTok, nextIdx >= 0)
		if dropFlag {
			drop[i] = true
			if dropVal && nextIdx >= 0 {
				drop[nextIdx] = true
			}
		}
	}

	// For each removed token, take one adjacent whitespace run with it:
	// the one after it, or the one before it when it ended the line or the
	// quoted argument.
	for i, d := range drop {
		if !d {
			continue
		}
		if j := i + 1; j < len(segs) && !segs[j].isToken && whitespaceOnly(line[segs[j].start:segs[j].end]) {
			drop[j] = true
			continue
		}
		if j := i - 1; j >= 0 && !segs[j].isToken && whitespaceOnly(line[segs[j].start:segs[j].end]) {
			drop[j] = true
		}
	}

	var b strings.Builder
	for i, sg := range segs {
		if !drop[i] {
			b.WriteString(line[sg.start:sg.end])
		}
	}
	return b.String()
}

func whitespaceOnly(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' && s[i] != '\t' {
			return false
		}
	}
	return len(s) > 0
}

// flagsInScript returns the replacements that would strip dangerous flags
// from one script, without writing anything.
func flagsInScript(path string) []flagEdit {
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 1<<20 {
		return nil
	}
	var edits []flagEdit
	for i, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") ||
			strings.HasPrefix(strings.TrimSpace(strings.ToLower(line)), "rem ") {
			continue // already commented out
		}
		cleaned := stripFlags(line)
		if cleaned != line {
			edits = append(edits, flagEdit{Line: i + 1, Was: line, Now: cleaned})
		}
	}
	return edits
}

// flagEdit is one line that would change if the exposing flags were removed.
type flagEdit struct {
	Line int
	Was  string
	Now  string
}

// LaunchScripts reports launch scripts that start an interface on the network.
func LaunchScripts(r *model.Report) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	for _, path := range findLaunchScripts(home) {
		edits := flagsInScript(path)
		if len(edits) == 0 {
			continue
		}

		var evidence, removed []string
		shared := false
		for _, e := range edits {
			evidence = append(evidence, fmt.Sprintf("line %d: %s", e.Line, strings.TrimSpace(e.Was)))
			for _, f := range flagsRemoved(e.Was, e.Now) {
				removed = appendUnique(removed, f)
				if f == "--share" {
					shared = true
				}
			}
		}
		sort.Strings(removed)

		sev, why := model.High, "This launch script binds the interface to every network interface, so anything that can route to this machine can open it."
		if shared {
			sev = model.Critical
			why = "This launch script publishes a public gradio.live tunnel. The link is unlisted rather than private, and it bypasses your router and firewall entirely."
		}

		r.Add(model.Finding{
			ID:       "CFG-003",
			Title:    fmt.Sprintf("%s starts an interface on the network", shortPath(home, path)),
			Severity: sev,
			Detail:   why + "\nFile: " + path,
			Evidence: evidence,
			Fix:      advice.RemoveFlags(path, removed),
		})
	}
}

// flagsRemoved names which flags disappeared between the original line and the
// cleaned one, so the advice can say what to delete rather than showing a diff.
func flagsRemoved(was, now string) []string {
	var out []string
	for _, f := range []string{"--share", "--listen", "--host", "--server-name"} {
		if strings.Contains(was, f) && !strings.Contains(now, f) {
			out = append(out, f)
		}
	}
	return out
}

func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

func shortPath(home, path string) string {
	if rel := strings.TrimPrefix(path, home); rel != path {
		return "~" + filepath.ToSlash(rel)
	}
	return path
}
