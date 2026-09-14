package supply

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// projectConfigNames are the files a repository uses to declare MCP servers.
var projectConfigNames = map[string]bool{
	".mcp.json": true, "mcp.json": true, "mcp_config.json": true,
	"claude_desktop_config.json": true, "settings.json": true,
}

// projectSkillDirs are directories whose immediate children are agent skills.
var projectSkillDirs = []string{
	filepath.Join(".claude", "skills"),
	"skills",
	filepath.Join(".cursor", "skills"),
}

const projectWalkDepth = 6

// TakeProject inventories a repository rather than a user's machine. It is what
// a CI job runs: the same components, discovered from files that are committed
// to the repo instead of installed under a home directory.
func TakeProject(root string) (Inventory, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return Inventory{}, err
	}
	if st, err := os.Stat(abs); err != nil || !st.IsDir() {
		return Inventory{}, err
	}

	inv := Inventory{Taken: time.Now().UTC(), OS: "repository"}
	budget := newBudget(30*time.Second, 200000)

	// Agent skills declared in the repo.
	for _, rel := range projectSkillDirs {
		dir := filepath.Join(abs, rel)
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			inv.Roots = append(inv.Roots, rel)
			inv.Artifacts = append(inv.Artifacts, dirArtifacts("agent-skill", dir, budget, Options{})...)
		}
	}

	// MCP configs and ComfyUI node trees, wherever they sit in the tree.
	_ = filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
		if err != nil || budget.spent() {
			return skipOn(err, budget)
		}
		rel, relErr := filepath.Rel(abs, path)
		if relErr != nil {
			return nil
		}
		if d.IsDir() {
			if skipDir(d.Name()) || depth(rel) > projectWalkDepth {
				return filepath.SkipDir
			}
			if d.Name() == "custom_nodes" {
				inv.Roots = append(inv.Roots, filepath.ToSlash(rel))
				inv.Artifacts = append(inv.Artifacts, dirArtifacts("comfy-node", path, budget, Options{})...)
				return filepath.SkipDir
			}
			return nil
		}
		if !projectConfigNames[strings.ToLower(d.Name())] {
			return nil
		}
		budget.file()
		if arts := mcpArtifacts(path); len(arts) > 0 {
			inv.Roots = append(inv.Roots, filepath.ToSlash(rel))
			inv.Artifacts = append(inv.Artifacts, arts...)
		}
		return nil
	})

	// Paths in a repository inventory are relative, so a lockfile committed to
	// git is identical on every machine and in every CI runner.
	for i := range inv.Artifacts {
		if rel, err := filepath.Rel(abs, inv.Artifacts[i].Path); err == nil {
			inv.Artifacts[i].Path = filepath.ToSlash(rel)
		}
		if cfg := inv.Artifacts[i].Detail["config"]; cfg != "" {
			if rel, err := filepath.Rel(abs, cfg); err == nil {
				inv.Artifacts[i].Detail["config"] = filepath.ToSlash(rel)
			}
		}
		for j := range inv.Artifacts[i].Indicators {
			if rel, err := filepath.Rel(abs, inv.Artifacts[i].Indicators[j].File); err == nil {
				inv.Artifacts[i].Indicators[j].File = filepath.ToSlash(rel)
			}
		}
	}

	if budget.spent() {
		inv.Skipped = append(inv.Skipped, "the repository scan hit its time or file budget and may be incomplete")
	}
	inv.Roots = dedupe(inv.Roots)
	sort.Slice(inv.Artifacts, func(i, j int) bool { return inv.Artifacts[i].ID < inv.Artifacts[j].ID })
	return inv, nil
}

func depth(rel string) int {
	if rel == "." {
		return 0
	}
	return strings.Count(filepath.ToSlash(rel), "/") + 1
}
