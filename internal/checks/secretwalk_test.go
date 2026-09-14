package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MC-kakadu/AIexpose/internal/model"
)

func openAIKey(tag string) string {
	return "sk-proj-" + strings.Repeat(tag, 44)[:44]
}

// walkRules is the minimum rule set these tests need. The real ones come from
// the signed feed; hard-coding a copy here would let the two drift apart, so
// only the shape is fixed, not the content.
func walkRules(t *testing.T) {
	t.Helper()
	prev := struct {
		pat  []keyPattern
		cfg  []string
		dirs []string
		nm   []string
		ext  []string
		doc  []string
		skip []string
		hist []string
	}{keyPatterns, configFiles, aiDirs, aiFileNames, searchExts, docDirs, skipDirs, historyFiles}
	t.Cleanup(func() {
		keyPatterns, configFiles, aiDirs, aiFileNames = prev.pat, prev.cfg, prev.dirs, prev.nm
		searchExts, docDirs, skipDirs, historyFiles = prev.ext, prev.doc, prev.skip, prev.hist
	})
	SetCredentialRules(CredentialRules{
		Patterns:    []CredentialPattern{{Vendor: "OpenAI", Pattern: `sk-proj-[A-Za-z0-9_-]{20,}`}},
		ConfigFiles: []string{".env"},
		SearchDirs:  []string{"ComfyUI"},
		SearchNames: []string{".env"},
		SearchExts:  []string{".txt", ".md"},
		DocDirs:     []string{"Desktop", "Documents"},
		SkipDirs:    []string{"node_modules"},
	})
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func secretIDs(r *model.Report) map[string]*model.Finding {
	out := map[string]*model.Finding{}
	for i := range r.Findings {
		out[r.Findings[i].ID] = &r.Findings[i]
	}
	return out
}

// A key written into keys.txt or into a note is the case an exact-filename
// list can never cover, and it is where people actually keep them.
func TestKeysInTextAndMarkdownFilesAreFound(t *testing.T) {
	walkRules(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	writeFile(t, filepath.Join(home, "keys.txt"), "openai "+openAIKey("A")+"\n")
	writeFile(t, filepath.Join(home, "ComfyUI", "custom_nodes", "x", "readme.md"), "key: "+openAIKey("B")+"\n")

	r := &model.Report{}
	Secrets(r, SecretScope{})

	f := secretIDs(r)["SEC-002"]
	if f == nil {
		t.Fatal("no SEC-002: a key in keys.txt and one in a node's readme.md were both missed")
	}
	joined := strings.Join(f.Evidence, "\n")
	for _, want := range []string{"keys.txt", "readme.md"} {
		if !strings.Contains(joined, want) {
			t.Errorf("evidence does not mention %s:\n%s", want, joined)
		}
	}
}

// The value must never appear in full, wherever it was found.
func TestWalkedKeysAreMasked(t *testing.T) {
	walkRules(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	secret := openAIKey("C")
	writeFile(t, filepath.Join(home, "notes.txt"), "key "+secret+"\n")

	r := &model.Report{}
	Secrets(r, SecretScope{})

	for _, f := range r.Findings {
		for _, e := range f.Evidence {
			if strings.Contains(e, secret) {
				t.Fatalf("the key was printed in full: %s", e)
			}
		}
		if strings.Contains(f.Detail, secret) {
			t.Fatal("the key appeared in a finding's detail")
		}
	}
}

// Document folders are opt-in, and the report has to say so. "Not found"
// without "here is where I did not look" is the false comfort this scanner
// has had to fix more than once.
func TestDocumentFoldersAreOptInAndSaidSo(t *testing.T) {
	walkRules(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	writeFile(t, filepath.Join(home, "Desktop", "api.md"), "key "+openAIKey("D")+"\n")

	r := &model.Report{}
	Secrets(r, SecretScope{})
	ids := secretIDs(r)
	if ids["SEC-002"] != nil {
		t.Error("Desktop was read without --scan-docs")
	}
	notRun := ids["SEC-004"]
	if notRun == nil {
		t.Fatal("no SEC-004: the report did not say the document folders were skipped")
	}
	if !notRun.NotRun {
		t.Error("SEC-004 is not marked NotRun, so it would appear under checks that passed")
	}

	r2 := &model.Report{}
	Secrets(r2, SecretScope{Docs: true})
	ids2 := secretIDs(r2)
	if ids2["SEC-002"] == nil {
		t.Fatal("--scan-docs did not find the key on the Desktop")
	}
	if ids2["SEC-004"] != nil {
		t.Error("SEC-004 still claims the document folders were skipped after --scan-docs")
	}
}

// A named folder covers the case the standard locations cannot: a work drive
// or a project directory outside the home folder.
func TestNamedFolderIsSearched(t *testing.T) {
	walkRules(t)
	home := t.TempDir()
	work := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	writeFile(t, filepath.Join(work, "project", "src", "notes.txt"), "key "+openAIKey("E")+"\n")

	r := &model.Report{}
	Secrets(r, SecretScope{Dirs: []string{work}})
	if secretIDs(r)["SEC-002"] == nil {
		t.Fatal("--scan-dir did not search the named folder")
	}
}

// Dependency trees hold thousands of files and no credential the user wrote
// down. Descending into them wastes the budget that would have found a real
// key somewhere else.
func TestDependencyTreesAreNotSearched(t *testing.T) {
	walkRules(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	writeFile(t, filepath.Join(home, "Documents", "node_modules", "p", "example.md"), "key "+openAIKey("F")+"\n")

	r := &model.Report{}
	Secrets(r, SecretScope{Docs: true})
	if f := secretIDs(r)["SEC-002"]; f != nil {
		t.Fatalf("node_modules was searched: %v", f.Evidence)
	}
}

// Only text files are opened at all. A model weight or an archive is never
// read, which is what keeps this bounded in both cost and privacy.
func TestOnlyTextFilesAreOpened(t *testing.T) {
	walkRules(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	writeFile(t, filepath.Join(home, "model.safetensors"), "key "+openAIKey("G")+"\n")
	writeFile(t, filepath.Join(home, "archive.zip"), "key "+openAIKey("H")+"\n")

	r := &model.Report{}
	Secrets(r, SecretScope{})
	if f := secretIDs(r)["SEC-002"]; f != nil {
		t.Fatalf("a non-text file was read: %v", f.Evidence)
	}
}

// Running out of budget must be reported. A search that quietly stopped and
// then said "none found" is the exact failure this project keeps meeting.
func TestHittingTheFileLimitIsReported(t *testing.T) {
	walkRules(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	for i := 0; i < walkMaxFiles+50; i++ {
		writeFile(t, filepath.Join(home, "Documents", "n", "f"+string(rune('a'+i%26))+string(rune('a'+i/26))+".txt"), "nothing\n")
	}

	r := &model.Report{}
	Secrets(r, SecretScope{Docs: true})
	f := secretIDs(r)["SEC-000"]
	if f == nil {
		t.Fatal("no SEC-000")
	}
	if !strings.Contains(f.Detail, "not a complete answer") {
		t.Errorf("a truncated search was reported as a clean result:\n%s", f.Detail)
	}
}

// The same unchanged machine must produce the same list, or the report is not
// comparable with yesterday's.
func TestWalkedHitsAreOrderedDeterministically(t *testing.T) {
	walkRules(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	for _, n := range []string{"b.txt", "a.txt", "c.md"} {
		writeFile(t, filepath.Join(home, n), "key "+openAIKey("A")+"\n")
	}

	var first []string
	for i := 0; i < 6; i++ {
		r := &model.Report{}
		Secrets(r, SecretScope{})
		f := secretIDs(r)["SEC-002"]
		if f == nil {
			t.Fatal("no SEC-002")
		}
		if i == 0 {
			first = f.Evidence
			continue
		}
		if strings.Join(f.Evidence, "|") != strings.Join(first, "|") {
			t.Fatalf("run %d differed:\n%v\nvs\n%v", i, f.Evidence, first)
		}
	}
}
