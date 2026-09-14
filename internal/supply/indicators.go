// Package supply inventories the parts of a local AI stack that can execute
// code — ComfyUI custom nodes, MCP servers, agent skills — fingerprints them,
// and detects when one of them changes after you installed it.
package supply

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/MC-kakadu/AIexpose/internal/model"
)

// Indicator is a high-signal pattern found inside an artifact's source.
type Indicator struct {
	ID       string         `json:"id"`
	Title    string         `json:"title"`
	Severity model.Severity `json:"-"`
	SevLabel string         `json:"severity"`
	File     string         `json:"file"`
	Line     int            `json:"line"`
	Excerpt  string         `json:"excerpt"`
}

// indicatorRule is a compiled detection pattern. The patterns themselves are
// not defined here: they are loaded from the signed feed by SetIndicatorRules,
// so they can be updated without a new binary and so this executable does not
// ship an infostealer's string table.
type indicatorRule struct {
	id    string
	title string
	sev   model.Severity
	re    *regexp.Regexp
}

// RuleSpec is one pattern as it arrives from the feed.
type RuleSpec struct {
	ID       string
	Title    string
	Severity model.Severity
	Pattern  string
}

var indicatorRules []indicatorRule

// SetIndicatorRules installs the detection patterns for this run. A pattern
// that does not compile is skipped and named, rather than aborting the scan:
// one bad rule in a feed must not disable every other check.
func SetIndicatorRules(specs []RuleSpec) []string {
	var skipped []string
	compiled := make([]indicatorRule, 0, len(specs))
	for _, s := range specs {
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			skipped = append(skipped, s.ID+": "+err.Error())
			continue
		}
		compiled = append(compiled, indicatorRule{id: s.ID, title: s.Title, sev: s.Severity, re: re})
	}
	indicatorRules = compiled
	return skipped
}

// IndicatorRuleCount reports how many patterns are loaded, for the report.
func IndicatorRuleCount() int { return len(indicatorRules) }

// scannedExts are the file types that actually execute.
var scannedExts = map[string]bool{
	".py": true, ".js": true, ".mjs": true, ".cjs": true, ".ts": true,
	".sh": true, ".bash": true, ".zsh": true, ".ps1": true, ".bat": true,
	".cmd": true, ".rb": true, ".pl": true, ".md": true, ".toml": true,
}

const (
	maxIndicatorFileBytes = 2 << 20
	maxExcerpt            = 120
	maxIndicatorsPerItem  = 25
)

// scanTree walks dir and returns every indicator match found in executable files.
func scanTree(dir string, budget *walkBudget) []Indicator {
	var out []Indicator
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || budget.spent() {
			return skipOn(err, budget)
		}
		if d.IsDir() {
			if skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !scannedExts[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		budget.file()
		out = append(out, scanSource(path)...)
		if len(out) >= maxIndicatorsPerItem {
			return filepath.SkipAll
		}
		return nil
	})
	if len(out) > maxIndicatorsPerItem {
		out = out[:maxIndicatorsPerItem]
	}
	return out
}

// scanText applies the detection patterns to text that is already in memory,
// such as a model's system prompt read out of a content-addressed blob.
func scanText(label, body string) []Indicator {
	var out []Indicator
	for lineNo, line := range strings.Split(body, "\n") {
		if len(line) > 8000 {
			line = line[:8000]
		}
		for _, rule := range indicatorRules {
			if !rule.re.MatchString(line) {
				continue
			}
			out = append(out, Indicator{
				ID: rule.id, Title: rule.title, Severity: rule.sev,
				SevLabel: rule.sev.String(),
				File:     label, Line: lineNo + 1, Excerpt: excerpt(line),
			})
			if len(out) >= maxIndicatorsPerItem {
				return out
			}
		}
	}
	return out
}

func scanSource(path string) []Indicator {
	info, err := os.Stat(path)
	if err != nil || info.Size() > maxIndicatorFileBytes {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []Indicator
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if len(line) > 8000 {
			line = line[:8000]
		}
		for _, rule := range indicatorRules {
			if !rule.re.MatchString(line) {
				continue
			}
			out = append(out, Indicator{
				ID: rule.id, Title: rule.title, Severity: rule.sev,
				SevLabel: rule.sev.String(),
				File:     path, Line: lineNo, Excerpt: excerpt(line),
			})
			if len(out) >= maxIndicatorsPerItem {
				return out
			}
		}
	}
	return out
}

func excerpt(line string) string {
	s := strings.TrimSpace(line)
	if len(s) > maxExcerpt {
		s = s[:maxExcerpt] + "..."
	}
	return s
}

func skipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "__pycache__", ".venv", "venv", "site-packages",
		".mypy_cache", ".pytest_cache", "dist-info", ".idea", ".vscode":
		return true
	}
	return false
}

func skipOn(err error, b *walkBudget) error {
	if b.spent() {
		return filepath.SkipAll
	}
	return nil
}
