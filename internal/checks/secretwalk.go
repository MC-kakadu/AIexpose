package checks

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// The caps below exist because this walk reads the user's own writing. A
// scanner that opens ten thousand documents is indistinguishable from an
// information stealer both to endpoint protection and to the person watching
// their disk light, and the honest report of "I looked at 400 files and
// stopped" is better than a scan that quietly grinds through a home
// directory.
const (
	walkMaxDepth = 4
	walkMaxFiles = 600
	walkMaxBytes = 512 << 10
)

// searchRoot is one place to look, with the label the report will use for it.
// The label matters: "not found" is only worth anything next to a list of
// where the looking happened.
type searchRoot struct {
	Path  string
	Label string
}

// walkResult carries what a walk did, not only what it found, so the report
// can say when a cap cut the search short rather than implying the folder was
// clean.
type walkResult struct {
	Hits      []hit
	Files     int
	Truncated bool
}

// textExt reports whether a file is one this search will open. Anything not
// on the list is skipped without being read at all -- images, archives and
// model weights are never opened, which keeps both the cost and the privacy
// surface to text the user wrote.
func textExt(name string, exts []string) bool {
	lower := strings.ToLower(name)
	// A dotfile with no extension (.env, .env.local, .npmrc) is still text.
	if strings.HasPrefix(lower, ".env") {
		return true
	}
	for _, e := range exts {
		if strings.HasSuffix(lower, e) {
			return true
		}
	}
	return false
}

// walkForKeys reads the text files under root, bounded on every axis.
func walkForKeys(root searchRoot, exts, skip []string, budget *int) walkResult {
	var res walkResult
	if root.Path == "" {
		return res
	}
	info, err := os.Stat(root.Path)
	if err != nil || !info.IsDir() {
		return res
	}
	skipSet := map[string]bool{}
	for _, d := range skip {
		skipSet[strings.ToLower(d)] = true
	}
	rootDepth := strings.Count(filepath.Clean(root.Path), string(os.PathSeparator))

	_ = filepath.WalkDir(root.Path, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable subdirectory is normal (permissions, a locked
			// OneDrive placeholder). Skipping it beats aborting the walk.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if *budget <= 0 {
			res.Truncated = true
			return filepath.SkipAll
		}
		if d.IsDir() {
			if path == root.Path {
				return nil
			}
			if skipSet[strings.ToLower(d.Name())] || strings.HasPrefix(d.Name(), ".git") {
				return fs.SkipDir
			}
			if strings.Count(filepath.Clean(path), string(os.PathSeparator))-rootDepth >= walkMaxDepth {
				return fs.SkipDir
			}
			return nil
		}
		if !textExt(d.Name(), exts) {
			return nil
		}
		fi, err := d.Info()
		if err != nil || fi.Size() > walkMaxBytes {
			return nil
		}
		*budget--
		res.Files++
		res.Hits = append(res.Hits, scanFile(path)...)
		return nil
	})
	return res
}

// searchRoots assembles the places to look, in the order the report lists
// them. Roots that do not exist are dropped here rather than reported as
// searched, because naming a folder that is not there as "checked" is the
// same false comfort as counting a check that never ran.
func searchRoots(home string, docs bool, extra []string) []searchRoot {
	var roots []searchRoot
	seen := map[string]bool{}
	add := func(path, label string) {
		if path == "" {
			return
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			abs = path
		}
		key := strings.ToLower(filepath.Clean(abs))
		if seen[key] {
			return
		}
		if fi, err := os.Stat(abs); err != nil || !fi.IsDir() {
			return
		}
		seen[key] = true
		roots = append(roots, searchRoot{Path: abs, Label: label})
	}

	for _, d := range aiDirs {
		add(filepath.Join(home, filepath.FromSlash(d)), d)
	}
	if docs {
		for _, d := range docDirs {
			add(filepath.Join(home, filepath.FromSlash(d)), d)
		}
		// OneDrive relocates Desktop and Documents on many Windows machines,
		// and the originals are then empty. Missing this is exactly the
		// "looked in the wrong place and reported nothing" failure.
		if od := os.Getenv("OneDrive"); od != "" {
			for _, d := range docDirs {
				add(filepath.Join(od, filepath.FromSlash(d)), "OneDrive/"+d)
			}
		}
	}
	for _, d := range extra {
		add(d, d)
	}
	sort.SliceStable(roots, func(i, j int) bool { return false })
	return roots
}

// homeTopLevel reads the text files sitting directly in the home directory,
// without descending. A key in ~/keys.txt is common and costs one directory
// read to find; walking the whole home directory is a different thing
// entirely, and that is what --scan-docs is for.
func homeTopLevel(home string, exts []string, budget *int) walkResult {
	var res walkResult
	entries, err := os.ReadDir(home)
	if err != nil {
		return res
	}
	for _, e := range entries {
		if *budget <= 0 {
			res.Truncated = true
			break
		}
		if e.IsDir() || !textExt(e.Name(), exts) {
			continue
		}
		fi, err := e.Info()
		if err != nil || fi.Size() > walkMaxBytes {
			continue
		}
		*budget--
		res.Files++
		res.Hits = append(res.Hits, scanFile(filepath.Join(home, e.Name()))...)
	}
	return res
}
