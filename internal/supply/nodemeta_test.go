package supply

import (
	"os"
	"path/filepath"
	"testing"
)

// Nodes installed from the Comfy Registry carry no .git directory at all, so
// every node on a desktop-app machine reported an empty version and source.
// The registry's own metadata file is what they do carry.
func TestPyprojectMetadataIsRead(t *testing.T) {
	dir := t.TempDir()
	body := `[project]
name = "rgthree-comfy"
version = "1.4.2"
license = { file = "LICENSE" }
dependencies = ["comfyui-frontend-package<=1.21.6"]

[project.urls]
Repository = "https://github.com/rgthree/rgthree-comfy"
Documentation = "https://example.invalid/docs"

[tool.comfy]
PublisherId = "rgthree"
DisplayName = "rgthree's ComfyUI Nodes"
includes = ['dist']
`
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	got := nodeMetadata(dir)
	for key, want := range map[string]string{
		"version":      "1.4.2",
		"origin":       "https://github.com/rgthree/rgthree-comfy",
		"publisher":    "rgthree",
		"display_name": "rgthree's ComfyUI Nodes",
		"metadata":     "pyproject.toml",
	} {
		if got[key] != want {
			t.Errorf("%s = %q, want %q", key, got[key], want)
		}
	}
}

// A git checkout is still the authority when there is one: it says where the
// code actually came from, which a file inside the package only claims.
func TestGitOriginWinsOverPyproject(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "config"),
		[]byte("[remote \"origin\"]\n\turl = https://github.com/real/source.git\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"),
		[]byte("[project.urls]\nRepository = \"https://github.com/claimed/other\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := nodeMetadata(dir)["origin"]; got != "https://github.com/real/source.git" {
		t.Errorf("origin = %q, want the git remote", got)
	}
}

// A wrong version in this report is worse than an absent one, so anything the
// reader cannot parse with certainty is skipped rather than guessed.
func TestUnparseableValuesAreSkipped(t *testing.T) {
	dir := t.TempDir()
	body := `[project]
name = "x"
version = 1.0
dynamic = ["version"]
description = """
a multi-line
string
"""
[tool.comfy]
PublisherId = "ok-publisher"
`
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got := nodeMetadata(dir)
	if v, ok := got["version"]; ok {
		t.Errorf("an unquoted version was read as %q", v)
	}
	if got["publisher"] != "ok-publisher" {
		t.Errorf("publisher = %q", got["publisher"])
	}
}

func TestNoMetadataIsNotAnError(t *testing.T) {
	if got := nodeMetadata(t.TempDir()); got != nil {
		t.Errorf("a bare directory produced %+v", got)
	}
}
