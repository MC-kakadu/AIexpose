package checks

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/MC-kakadu/AIexpose/internal/model"
)

// The product promise is that a scan reads and never changes the machine.
// Earlier versions rewrote launch scripts, set environment variables and
// deleted router port mappings; that code is gone, and this test is what stops
// it coming back by accident.
func TestScanNeverModifiesTheMachine(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("OLLAMA_HOST", "0.0.0.0:11434")
	t.Setenv("OLLAMA_ORIGINS", "*")

	write := func(rel, body string) {
		p := filepath.Join(home, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The things a scan has opinions about: a launch script with --listen and
	// --share, a profile holding a key, and a model file.
	write("stable-diffusion-webui/webui-user.sh", "#!/bin/bash\nexport COMMANDLINE_ARGS=\"--listen --share --api\"\n")
	write(".bashrc", "export OPENAI_API_KEY=sk-proj-AbCdEf1234567890QwErTyUiOpAsDfGh\n")
	write(".env", "ANTHROPIC_API_KEY=sk-ant-api03-AbCdEf1234567890QwErTyUiOp\n")
	write(".cache/torch/hub/checkpoints/resnet.pth", "not really weights")

	before := snapshot(t, home)

	SetCredentialRules(CredentialRules{
		Patterns: []CredentialPattern{
			{Vendor: "Anthropic", Pattern: `sk-ant-[A-Za-z0-9_\-]{20,}`},
			{Vendor: "OpenAI", Pattern: `sk-(?:proj-)?[A-Za-z0-9_\-]{20,}`},
		},
		ConfigFiles: []string{".bashrc", ".env"},
	})
	defer SetCredentialRules(CredentialRules{})

	r := &model.Report{}
	Environment(r)
	LaunchScripts(r)
	Secrets(r, SecretScope{})
	ModelFormats(r)
	r.Finalize()

	// The scan has to have actually found something, or this proves nothing.
	if len(r.Findings) == 0 {
		t.Fatal("the fixture produced no findings, so the test is not exercising anything")
	}
	var withCommand int
	for _, f := range r.Findings {
		if f.Command != "" {
			withCommand++
		}
	}
	if withCommand == 0 {
		t.Error("no finding offered a command; suggestions are the whole point now")
	}

	if diff := compare(before, snapshot(t, home)); diff != "" {
		t.Fatalf("the scan changed the machine: %s", diff)
	}
}

type fileState struct {
	size int64
	mode fs.FileMode
	body string
}

func snapshot(t *testing.T, root string) map[string]fileState {
	t.Helper()
	out := map[string]fileState{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // unreadable entries are not our concern here
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		out[filepath.ToSlash(rel)] = fileState{info.Size(), info.Mode().Perm(), string(body)}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func compare(before, after map[string]fileState) string {
	for name, b := range before {
		a, ok := after[name]
		if !ok {
			return name + " was deleted"
		}
		if a.body != b.body {
			return name + " was rewritten"
		}
		if a.mode != b.mode {
			return name + " had its permissions changed"
		}
	}
	for name := range after {
		if _, ok := before[name]; !ok {
			return name + " was created"
		}
	}
	return ""
}
