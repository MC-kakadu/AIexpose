package checks

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/MC-kakadu/AIexpose/internal/advice"
	"github.com/MC-kakadu/AIexpose/internal/model"
)

type keyPattern struct {
	vendor string
	re     *regexp.Regexp
	sev    model.Severity
}

// The credential patterns and the locations to search are supplied by the
// signed feed rather than compiled in. New providers appear constantly, so
// these need to reach users without a binary release -- and a list of key
// prefixes next to a list of shell history paths is, character for character,
// what an information stealer carries, which is why endpoint protection
// quarantines tools that embed one.
var (
	keyPatterns  []keyPattern
	historyFiles []string
	configFiles  []string
	aiDirs       []string
	aiFileNames  []string
	searchExts   []string
	docDirs      []string
	skipDirs     []string
)

// CredentialRules is one vendor key pattern as it arrives from the feed.
type CredentialRules struct {
	Patterns     []CredentialPattern
	HistoryFiles []string
	ConfigFiles  []string
	SearchDirs   []string
	SearchNames  []string
	SearchExts   []string
	DocDirs      []string
	SkipDirs     []string
}

// CredentialPattern is a single vendor's key shape.
type CredentialPattern struct {
	Vendor  string
	Pattern string
}

// SetCredentialRules installs the credential detection rules for this run and
// returns the ones that could not be compiled.
func SetCredentialRules(r CredentialRules) []string {
	var skipped []string
	compiled := make([]keyPattern, 0, len(r.Patterns))
	for _, p := range r.Patterns {
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			skipped = append(skipped, p.Vendor+": "+err.Error())
			continue
		}
		// Every credential is worth the same: the damage is the key leaking,
		// not which service it opens.
		compiled = append(compiled, keyPattern{vendor: p.Vendor, re: re, sev: model.High})
	}
	keyPatterns = compiled
	historyFiles = fromSlash(r.HistoryFiles)
	configFiles = fromSlash(r.ConfigFiles)
	aiDirs = r.SearchDirs
	aiFileNames = r.SearchNames
	searchExts = lowerAll(r.SearchExts)
	docDirs = r.DocDirs
	skipDirs = r.SkipDirs
	return skipped
}

func lowerAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.ToLower(s))
	}
	return out
}

// CredentialRuleCount reports how many key patterns are loaded.
func CredentialRuleCount() int { return len(keyPatterns) }

// fromSlash converts the feed's portable "/" paths to this platform's form.
func fromSlash(in []string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		out = append(out, filepath.FromSlash(p))
	}
	return out
}

const (
	maxFileBytes = 4 << 20
	maxHits      = 40
)

type hit struct {
	vendor string
	file   string
	line   int
	masked string
	sev    model.Severity
}

// SecretScope says how far the credential search may reach. Every widening of
// it is something the user asked for by name, because each one moves the tool
// closer to the behaviour of the thing it is looking for.
type SecretScope struct {
	// History reads shell and PowerShell history (--scan-history).
	History bool
	// Docs reads the personal document folders (--scan-docs).
	Docs bool
	// Dirs are folders the user named explicitly (--scan-dir).
	Dirs []string
}

// Secrets looks for plaintext API keys. Matched values are always masked
// before they are reported.
func Secrets(r *model.Report, scope SecretScope) {
	scanHistory := scope.History
	home, err := os.UserHomeDir()
	if err != nil {
		r.Note("Home directory could not be resolved; the credential check was skipped.")
		return
	}

	var (
		histHits []hit
		cfgHits  []hit
	)

	// Shell history is where a leaked key does the most damage, and also the
	// first thing an information stealer collects. Reading it is therefore the
	// most malware-shaped action in this tool, and a behaviour engine watching
	// an unsigned binary will treat it as such -- so the user asks for it.
	if scanHistory {
		for _, rel := range historyFiles {
			histHits = append(histHits, scanFile(filepath.Join(home, rel))...)
		}
	}
	for _, rel := range configFiles {
		cfgHits = append(cfgHits, scanFile(filepath.Join(home, rel))...)
	}
	for _, d := range aiDirs {
		base := filepath.Join(home, filepath.FromSlash(d))
		for _, name := range aiFileNames {
			cfgHits = append(cfgHits, scanFile(filepath.Join(base, name))...)
		}
	}

	// An exact-name list can only find files someone else named. Keys written
	// down by hand live in keys.txt, in api.md, in a file called "í¤.txt" --
	// names no list will ever hold. So the search is by file kind, inside a
	// bounded set of places.
	budget := walkMaxFiles
	var (
		searched  []string
		filesRead int
		truncated bool
		cutShort  []string
	)
	if len(searchExts) > 0 && len(keyPatterns) > 0 {
		top := homeTopLevel(home, searchExts, &budget)
		cfgHits = append(cfgHits, top.Hits...)
		filesRead += top.Files
		truncated = truncated || top.Truncated
		searched = append(searched, "the home folder itself")

		// Each root gets its own share of the budget. First-come-first-served
		// let one noisy folder -- a Documents full of exported notes -- eat
		// the whole allowance and hide a key sitting on the Desktop. A folder
		// running out of room is reported; a folder never reached is not,
		// and that is the difference that matters.
		roots := searchRoots(home, scope.Docs, scope.Dirs)
		for i, root := range roots {
			left := len(roots) - i
			share := budget / left
			if share < 1 {
				share = 1
			}
			spend := share
			res := walkForKeys(root, searchExts, skipDirs, &spend)
			used := share - spend
			budget -= used
			cfgHits = append(cfgHits, res.Hits...)
			filesRead += res.Files
			truncated = truncated || res.Truncated
			label := root.Label
			if res.Truncated {
				label += " (stopped early)"
				cutShort = append(cutShort, root.Label)
			}
			searched = append(searched, label)
		}
		cfgHits = dedupeHits(cfgHits)
	}

	if len(histHits) > 0 {
		r.Add(model.Finding{
			ID:       "SEC-001",
			Title:    fmt.Sprintf("%d API key(s) found in shell history", len(histHits)),
			Severity: model.High,
			Detail:   "Shell history is world-readable to any process running as you, is copied by every backup and sync tool, and is one of the first files an infostealer collects. Stolen inference keys are resold and can run up five-figure daily bills.",
			Evidence: evidenceFor(histHits),
			Fix:      "Rotate every key listed above at the provider, remove the lines from the history file, and load keys from a secrets manager or a file with 0600 permissions instead of typing them at the prompt.",
		})
	}
	if len(cfgHits) > 0 {
		f := model.Finding{
			ID:       "SEC-002",
			Title:    fmt.Sprintf("%d API key(s) stored in plaintext config files", len(cfgHits)),
			Severity: model.Medium,
			Detail: "Keys in shell profiles and .env files are exported into every process you launch, " +
				"including any AI tool or extension you install. Keys written into a note or a text file are " +
				"worse in a different way: nothing exports them, so nothing rotates them either, and they are " +
				"copied by every backup, sync client and screen share.",
			Evidence: evidenceFor(cfgHits),
			Fix: "Rotate each key at its provider first; restricting the file does not undo a key that already leaked. " +
				"Then move them into your OS keychain or a secrets manager, and make sure .env is in .gitignore." +
				remainingFilesNote(cfgHits),
			Command: restrictCommand(cfgHits),
		}
		// Where the search reached belongs on the finding that found
		// something, not only on the one that found nothing. A list of seven
		// keys means something different if the search covered two folders
		// than if it covered eight.
		f.Detail += "\n\n" + scopeSentence(searched, filesRead, truncated)
		r.Add(f)
	}
	if len(keyPatterns) == 0 {
		r.Note("No credential patterns are loaded, so no key scan was performed. " +
			"Install them with: " + selfCommand("--install-rules "+rulesFileToSuggest()))
		return
	}

	if !scanHistory {
		r.Add(model.Finding{
			ID:       "SEC-003",
			Title:    "Shell history was not searched for API keys",
			Severity: model.Info,
			NotRun:   true,
			Detail: "Shell and PowerShell history is where typed credentials survive longest, and it is " +
				"copied by every backup and sync tool. It is not searched by default because reading it " +
				"is the same action an information stealer performs, and endpoint protection blocks " +
				"unsigned programs that do it.",
			Fix:     "Search it explicitly:",
			Command: selfCommand("--scan-history"),
		})
	}

	// Every credential finding is worth exactly as much as the list of places
	// that were looked at. "None found" with no scope attached is the shape of
	// false comfort this scanner has had to fix more than once.
	if !scope.Docs {
		r.Add(model.Finding{
			ID:       "SEC-004",
			Title:    "Your document folders were not searched for API keys",
			Severity: model.Info,
			NotRun:   true,
			Detail: "Desktop, Documents and Downloads were not read. They are not searched by default " +
				"because walking a person's documents and reading every text file is precisely what an " +
				"information stealer does, and an unsigned tool that does it unasked gets quarantined -- " +
				"rightly.\n" +
				"If you have ever pasted a key into a note to keep it handy, that is where it is.",
			Fix:     "Search them, or name a folder of your own:",
			Command: selfCommand("--scan-docs"),
		})
	}

	if len(histHits) == 0 && len(cfgHits) == 0 {
		where := "Shell profiles and common .env locations were checked."
		if scanHistory {
			where = "Shell history, shell profiles and common .env locations were checked."
		}
		if s := scopeSentence(searched, filesRead, truncated); s != "" {
			where += "\n" + s
		}
		r.Add(model.Finding{
			ID: "SEC-000", Title: "No plaintext API keys found in the places checked",
			Severity: model.Info,
			Detail:   where,
		})
	}
	_ = cutShort

}

// evidenceFor lists every hit. The value is always masked, including here.
// restrictCommand names the first offending file: one copyable line is more
// use than a list the reader has to assemble themselves.
func restrictCommand(hits []hit) string {
	if len(hits) == 0 {
		return ""
	}
	return advice.RestrictFile(hits[0].file)
}

// remainingFilesNote says that the copyable command covers one file out of
// several.
//
// The command is one line on purpose -- a wall of them is not copyable -- but a
// finding headed "2 API key(s)" followed by a single command reads as the whole
// fix, and a reader who runs it has secured half of what was found without
// anything telling them so. The evidence list says where the keys are; this
// says how much of the work the button does.
func remainingFilesNote(hits []hit) string {
	files := distinctFiles(hits)
	if len(files) < 2 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n\nThe command below restricts one file. %d file(s) hold keys, so run the "+
		"equivalent for each of the others too:", len(files))
	for _, f := range files[1:] {
		b.WriteString("\n  " + advice.RestrictFile(f))
	}
	return b.String()
}

// distinctFiles lists the files hits came from, first-seen order preserved so
// the head of the list is the file restrictCommand names.
func distinctFiles(hits []hit) []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range hits {
		if seen[h.file] {
			continue
		}
		seen[h.file] = true
		out = append(out, h.file)
	}
	return out
}

func evidenceFor(hits []hit) []string {
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		out = append(out, fmt.Sprintf("%s key  %s:%d  %s", h.vendor, h.file, h.line, h.masked))
	}
	return out
}

func scanFile(path string) []hit {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() > maxFileBytes {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []hit
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		out = append(out, scanLine(path, lineNo, sc.Text())...)
		if len(out) >= maxHits {
			return out[:maxHits]
		}
	}
	return out
}

// span is a claimed byte range within one line.
type span struct{ start, end int }

// scanLine reports one hit per credential. A value such as sk-ant-... matches
// both the Anthropic rule and the broader OpenAI rule, so once a pattern claims
// a range no later pattern may report anything overlapping it.
func scanLine(path string, lineNo int, line string) []hit {
	var claimed []span
	var out []hit

	for _, kp := range keyPatterns {
		for _, idx := range kp.re.FindAllStringIndex(line, -1) {
			if overlaps(claimed, idx[0], idx[1]) {
				continue
			}
			if !looksLikeKeyMaterial(line[idx[0]:idx[1]]) {
				continue
			}
			claimed = append(claimed, span{idx[0], idx[1]})
			out = append(out, hit{
				vendor: kp.vendor,
				file:   path,
				line:   lineNo,
				masked: model.MaskSecret(line[idx[0]:idx[1]]),
				sev:    kp.sev,
			})
		}
	}
	return out
}

func overlaps(claimed []span, start, end int) bool {
	for _, c := range claimed {
		if start < c.end && end > c.start {
			return true
		}
	}
	return false
}

// dedupeHits removes the same key found twice at the same place, which happens
// when a folder is reachable by two roots (Documents and OneDrive/Documents
// are the same directory on many Windows machines). Reporting one key twice
// makes the count wrong, and the count is what the user acts on.
func dedupeHits(in []hit) []hit {
	seen := map[string]bool{}
	out := make([]hit, 0, len(in))
	for _, h := range in {
		key := h.file + "\x00" + fmt.Sprint(h.line) + "\x00" + h.masked
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, h)
	}
	// A stable order keeps two scans of an unchanged machine identical.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].file != out[j].file {
			return out[i].file < out[j].file
		}
		if out[i].line != out[j].line {
			return out[i].line < out[j].line
		}
		return out[i].vendor < out[j].vendor
	})
	return out
}

// scopeSentence states what the credential search actually covered.
//
// It goes on every credential finding, not just the empty one. "Seven keys
// found" and "no keys found" are both answers to the question "in which
// folders?", and a reader who cannot see the scope cannot tell a thorough
// scan from a narrow one.
func scopeSentence(searched []string, files int, truncated bool) string {
	if files == 0 {
		return ""
	}
	s := fmt.Sprintf("Searched %d text file(s) under: %s.", files, strings.Join(searched, ", "))
	s += " Only text files were opened (" + strings.Join(searchExts, " ") +
		"), no deeper than " + fmt.Sprint(walkMaxDepth) + " folders, and nothing over " +
		humanSize(walkMaxBytes) + "."
	if truncated {
		s += fmt.Sprintf(" The search stopped at its %d-file limit in the folder marked above, "+
			"so this is not a complete answer: point --scan-dir at that folder to finish it.", walkMaxFiles)
	}
	return s
}
