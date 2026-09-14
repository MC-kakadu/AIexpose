package checks

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MC-kakadu/AIexpose/internal/control"
	"github.com/MC-kakadu/AIexpose/internal/hashdb"
	"github.com/MC-kakadu/AIexpose/internal/model"
	"github.com/MC-kakadu/AIexpose/internal/supply"
)

// fakeStack builds a ComfyUI custom_nodes tree holding one node with a source
// file and one compiled file, and points the scanner at it.
// realistic pads a payload past minHashSize. Nothing under that is matched any
// more, so a fixture below it tests the skip rule rather than the match.
func realistic(s string) []byte {
	b := []byte(s)
	for len(b) < minHashSize*2 {
		b = append(b, []byte(" filler bytes so this file is a plausible size")...)
	}
	return b
}

func fakeStack(t *testing.T, payload []byte) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	node := filepath.Join(home, "ComfyUI", "custom_nodes", "some-node")
	if err := os.MkdirAll(node, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(node, "__init__.py"), realistic("print(1)"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(node, "helper.dll"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("COMFYUI_PATH", filepath.Join(home, "ComfyUI"))
	return home
}

// indexContaining builds a real index holding exactly these payload hashes.
func indexContaining(t *testing.T, payloads ...[]byte) string {
	t.Helper()
	src := t.TempDir()
	var body strings.Builder
	body.WriteString("################################\n# Malware sample MD5 list      #\n")
	for _, p := range payloads {
		sum := md5.Sum(p)
		body.WriteString(hex.EncodeToString(sum[:]) + "\n")
	}
	if err := os.WriteFile(filepath.Join(src, "VirusShare_00000.md5"), []byte(body.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "hashdb.bin")
	if _, err := hashdb.Build(src, out, nil); err != nil {
		t.Fatal(err)
	}
	return out
}

func md5hex(b []byte) string {
	sum := md5.Sum(b)
	return hex.EncodeToString(sum[:])
}

func findingByID(r *model.Report, id string) *model.Finding {
	for i := range r.Findings {
		if r.Findings[i].ID == id {
			return &r.Findings[i]
		}
	}
	return nil
}

func runSupply(t *testing.T, home string, opt SupplyOptions) *model.Report {
	t.Helper()
	if opt.BaselinePath == "" {
		opt.BaselinePath = filepath.Join(t.TempDir(), "baseline.json")
	}
	opt.DisableFeed = true
	r := &model.Report{}
	SupplyChain(r, opt)
	r.Finalize()
	return r
}

func TestMalwareHashMatchIsReported(t *testing.T) {
	payload := realistic("MZ\x90\x00 pretend this is a stealer")
	home := fakeStack(t, payload)
	index := indexContaining(t, payload)

	r := runSupply(t, home, SupplyOptions{HashDBPath: index})

	f := findingByID(r, "SUP-050")
	if f == nil {
		var ids []string
		for _, x := range r.Findings {
			ids = append(ids, x.ID)
		}
		t.Fatalf("no SUP-050 finding; got %v", ids)
	}
	if f.Severity != model.Critical {
		t.Errorf("severity = %v, want Critical", f.Severity)
	}
	if !strings.Contains(strings.Join(f.Evidence, "\n"), "helper.dll") {
		t.Errorf("the matched file was not named in the evidence: %v", f.Evidence)
	}
	if findingByID(r, "SUP-052") != nil {
		t.Error("a clean-result finding was reported alongside a match")
	}
}

// A source file is hashed too: a corpus rarely holds Python, but if it does,
// the match still has to surface.
func TestMalwareHashMatchesSourceFilesToo(t *testing.T) {
	source := realistic("print(1)")
	home := fakeStack(t, realistic("harmless binary"))
	index := indexContaining(t, source)

	r := runSupply(t, home, SupplyOptions{HashDBPath: index})

	f := findingByID(r, "SUP-050")
	if f == nil {
		t.Fatal("a matching __init__.py did not produce a finding")
	}
	if !strings.Contains(strings.Join(f.Evidence, "\n"), "__init__.py") {
		t.Errorf("evidence did not name the source file: %v", f.Evidence)
	}
}

func TestCleanStackReportsNoMatch(t *testing.T) {
	home := fakeStack(t, realistic("perfectly ordinary bytes"))
	index := indexContaining(t, realistic("something else entirely"))

	r := runSupply(t, home, SupplyOptions{HashDBPath: index})

	if f := findingByID(r, "SUP-050"); f != nil {
		t.Fatalf("a clean file was reported as malware: %v", f.Evidence)
	}
	f := findingByID(r, "SUP-052")
	if f == nil {
		t.Fatal("no SUP-052 finding, so the report does not say the check ran")
	}
	if f.Severity != model.Info {
		t.Errorf("severity = %v, want Info", f.Severity)
	}
	// The count has to be real, or the reassurance is empty.
	if !strings.Contains(f.Title, "2 file(s)") {
		t.Errorf("title = %q, want the two hashed files counted", f.Title)
	}
}

// Nobody has an index on a first run. That must read as an unused option, not
// as a broken scan: an Advisory here would put an "incomplete" badge on every
// report ever produced.
func TestMissingIndexIsInformationalNotIncomplete(t *testing.T) {
	home := fakeStack(t, realistic("ordinary"))

	r := runSupply(t, home, SupplyOptions{HashDBPath: filepath.Join(t.TempDir(), "absent.bin")})

	f := findingByID(r, "SUP-051")
	if f == nil {
		t.Fatal("no SUP-051 finding, so the feature is invisible to anyone who has not found the flag")
	}
	if f.Severity != model.Info {
		t.Errorf("severity = %v, want Info", f.Severity)
	}
	if f.Advisory {
		t.Error("SUP-051 is Advisory, which marks every default report incomplete")
	}
	if r.Incomplete {
		t.Error("the report is marked incomplete because an opt-in extra is not installed")
	}
	if f.Command == "" {
		t.Error("SUP-051 offers no command, so the user is told about a feature with no way to enable it")
	}
}

func TestDisableSkipsTheCheckEntirely(t *testing.T) {
	payload := realistic("MZ\x90\x00 pretend this is a stealer")
	home := fakeStack(t, payload)
	index := indexContaining(t, payload)

	r := runSupply(t, home, SupplyOptions{HashDBPath: index, DisableHashDB: true})

	for _, id := range []string{"SUP-050", "SUP-051", "SUP-052"} {
		if f := findingByID(r, id); f != nil {
			t.Errorf("%s was reported despite --no-hashdb", id)
		}
	}
	if len(r.Notes) == 0 {
		t.Error("skipping the check left no note in the report")
	}
}

// With no index there is nothing to compare against, so the scan must not pay
// to open binaries it has no use for.
func TestBinariesAreNotHashedWithoutAnIndex(t *testing.T) {
	home := fakeStack(t, realistic("ordinary"))
	r := &model.Report{}
	res := SupplyChain(r, SupplyOptions{
		BaselinePath:  filepath.Join(t.TempDir(), "baseline.json"),
		DisableFeed:   true,
		DisableHashDB: true,
	})
	_ = home
	for _, a := range res.Inventory.Artifacts {
		if len(a.Hashes) != 0 {
			t.Errorf("%s collected %d file hashes with no index to match them against", a.ID, len(a.Hashes))
		}
	}
}

// A corrupt index must degrade to "this check did not run", never to a silent
// pass that says nothing matched.
func TestCorruptIndexIsReportedNotIgnored(t *testing.T) {
	home := fakeStack(t, realistic("ordinary"))
	bad := filepath.Join(t.TempDir(), "hashdb.bin")
	if err := os.WriteFile(bad, []byte("this is not an index"), 0o600); err != nil {
		t.Fatal(err)
	}

	r := runSupply(t, home, SupplyOptions{HashDBPath: bad})

	f := findingByID(r, "SUP-051")
	if f == nil {
		t.Fatal("a corrupt index produced no finding")
	}
	if f.Severity != model.Low {
		t.Errorf("severity = %v, want Low: a broken index is a gap, not a normal state", f.Severity)
	}
	if findingByID(r, "SUP-052") != nil {
		t.Error("a corrupt index still produced a clean-result finding")
	}
}

// A check that hashed nothing must never be reported as a check that passed.
// This is the same false-pass shape as the empty-list bug fixed in v0.8.1, and
// a real Windows report showed it again: a 244 MB index, 0 files checked, and a
// green "no match" line.
func TestZeroFilesCheckedIsNotAPass(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	index := indexContaining(t, realistic("something"))

	r := runSupply(t, home, SupplyOptions{HashDBPath: index})

	if f := findingByID(r, "SUP-052"); f != nil {
		t.Errorf("a scan that hashed nothing reported %q as a result", f.Title)
	}
	f := findingByID(r, "SUP-053")
	if f == nil {
		t.Fatal("no SUP-053: the report says nothing about the check having had no input")
	}
	if !f.NotRun {
		t.Error("SUP-053 is not marked NotRun, so it will be filed under checks that passed")
	}
	if f.Advisory {
		t.Error("SUP-053 is Advisory, which marks the whole report incomplete")
	}
	if !strings.Contains(f.Detail, "not a pass") {
		t.Error("SUP-053 does not say plainly that this is not a pass")
	}
}

// The model files the format check already walked are the only thing to hash on
// a machine whose AI stack is just a model runner.
func TestModelFilesAreHashed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	payload := realistic("a poisoned checkpoint")
	dir := filepath.Join(home, ".cache", "torch", "hub", "checkpoints")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	small := filepath.Join(dir, "bad.pth")
	if err := os.WriteFile(small, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	index := indexContaining(t, payload)

	weights := ModelInventory{Files: []WeightFile{
		{Path: small, Size: int64(len(payload))},
		{Path: filepath.Join(dir, "huge.bin"), Size: weightHashLimit + 1},
	}}
	r := runSupply(t, home, SupplyOptions{HashDBPath: index, Weights: weights})

	f := findingByID(r, "SUP-050")
	if f == nil {
		t.Fatal("a model file matching the corpus produced no finding")
	}
	if !strings.Contains(strings.Join(f.Evidence, "\n"), "bad.pth") {
		t.Errorf("evidence does not name the matched file: %v", f.Evidence)
	}
}

// A count of files checked means little without saying what was passed over.
func TestOversizeWeightsAreCounted(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	dir := t.TempDir()
	clean := realistic("clean weights")
	small := filepath.Join(dir, "ok.pt")
	if err := os.WriteFile(small, clean, 0o644); err != nil {
		t.Fatal(err)
	}
	index := indexContaining(t, realistic("unrelated"))

	weights := ModelInventory{Files: []WeightFile{
		{Path: small, Size: int64(len(clean))},
		{Path: filepath.Join(dir, "a.bin"), Size: weightHashLimit + 1},
		{Path: filepath.Join(dir, "b.bin"), Size: weightHashLimit * 10},
	}}
	r := runSupply(t, home, SupplyOptions{HashDBPath: index, Weights: weights})

	f := findingByID(r, "SUP-052")
	if f == nil {
		t.Fatal("no result finding")
	}
	if !strings.Contains(f.Title, "1 file(s) checked") {
		t.Errorf("title = %q, want 1 file counted", f.Title)
	}
	if !strings.Contains(f.Detail, "2 file(s) were skipped for being larger") {
		t.Errorf("detail does not say how many were skipped for size: %q", f.Detail)
	}
}

// Every command a report prints has to name the executable the reader actually
// has. "aiexpose --accept" is not a command on a machine whose file is called
// aiexpose_0.17.1_windows_amd64.exe.
func TestPrintedCommandsNameThisExecutable(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip("this platform cannot resolve its own path")
	}
	base := filepath.Base(exe)

	for _, got := range []string{acceptCommand(), buildHashDBCommand(), selfCommand("--scan-history")} {
		if !strings.Contains(got, base) {
			t.Errorf("%q does not name this executable (%s)", got, base)
		}
		if strings.HasPrefix(got, "aiexpose ") {
			t.Errorf("%q falls back to the generic name while the real one is known", got)
		}
	}
}

// The bug that made a real machine grade F/0 on three false criticals.
//
// Hugging Face fills .no_exist/ with EMPTY files to record which optional files
// a repo does not have. Every one of them has the MD5 of the empty string --
// and that hash is in VirusShare, because trivial files get submitted as
// samples. Hashing them told a user their machine was compromised and to rotate
// every credential they own.
func TestEmptyAndTinyFilesAreNeverMatched(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	// A corpus that contains the empty file's hash, exactly as VirusShare does.
	src := t.TempDir()
	body := "# banner\n" + "d41d8cd98f00b204e9800998ecf8427e\n" + md5hex(realistic("something real")) + "\n"
	if err := os.WriteFile(filepath.Join(src, "VirusShare_00000.md5"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "hashdb.bin")
	if _, err := hashdb.Build(src, out, nil); err != nil {
		t.Fatal(err)
	}

	marker := filepath.Join(home, "empty.safetensors")
	if err := os.WriteFile(marker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	tiny := filepath.Join(home, "tiny.pt")
	if err := os.WriteFile(tiny, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := runSupply(t, home, SupplyOptions{HashDBPath: out, Weights: ModelInventory{Files: []WeightFile{
		{Path: marker, Size: 0},
		{Path: tiny, Size: 1},
	}}})

	if f := findingByID(r, "SUP-050"); f != nil {
		t.Fatalf("an empty marker file was reported as malware: %v", f.Evidence)
	}
	if r.Grade == "F" {
		t.Error("empty files dragged the grade to F")
	}
	f := findingByID(r, "SUP-053")
	if f == nil {
		t.Fatal("nothing was hashable, but the report does not say so")
	}
	if !strings.Contains(f.Detail, "under 64 bytes") {
		t.Errorf("the report does not explain why the tiny files were skipped: %q", f.Detail)
	}
}

// Hugging Face bookkeeping directories must not be walked at all: their
// contents are records, not models, and counting them inflates every total.
func TestHuggingFaceBookkeepingIsSkipped(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	repo := filepath.Join(home, ".cache", "huggingface", "hub", "models--a--b")
	real := filepath.Join(repo, "snapshots", "abc")
	marker := filepath.Join(repo, ".no_exist", "abc")
	for _, d := range []string{real, marker, filepath.Join(repo, ".locks")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(real, "model.safetensors"), realistic("weights"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The marker the library writes for a file the repo does not have.
	if err := os.WriteFile(filepath.Join(marker, "model.safetensors"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	r := &model.Report{}
	inv := ModelFormats(r)

	for _, f := range inv.Files {
		if strings.Contains(f.Path, ".no_exist") || strings.Contains(f.Path, ".locks") {
			t.Errorf("bookkeeping file was inventoried as a model: %s", f.Path)
		}
	}
	if len(inv.Files) != 1 {
		t.Fatalf("inventoried %d files, want only the real one: %v", len(inv.Files), inv.Files)
	}
	if f := findingByID(r, "MDL-000"); f != nil && !strings.Contains(f.Title, "1 ") {
		t.Errorf("safe-format count is inflated by marker files: %q", f.Title)
	}
}

// Three files sharing one hash is one fact, not three infections. Reporting it
// as three criticals is what buried the degenerate-hash bug.
func TestIdenticalHashesAreGroupedIntoOneFinding(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	payload := realistic("the same bytes in three places")
	index := indexContaining(t, payload)

	var files []WeightFile
	for _, n := range []string{"a.pt", "b.pt", "c.pt"} {
		p := filepath.Join(home, n)
		if err := os.WriteFile(p, payload, 0o644); err != nil {
			t.Fatal(err)
		}
		files = append(files, WeightFile{Path: p, Size: int64(len(payload))})
	}

	r := runSupply(t, home, SupplyOptions{HashDBPath: index, Weights: ModelInventory{Files: files}})

	var n int
	for _, f := range r.Findings {
		if f.ID == "SUP-050" {
			n++
			if len(f.Evidence) != 3 {
				t.Errorf("the finding lists %d files, want all 3", len(f.Evidence))
			}
			if !strings.Contains(f.Title, "3 files match the same") {
				t.Errorf("title = %q, want it to say one hash covers three files", f.Title)
			}
		}
	}
	if n != 1 {
		t.Errorf("%d separate criticals for one hash, want 1", n)
	}
}

// A model you pulled yourself an hour ago is unreviewed, not dangerous. The
// component table must not paint it the same colour as a malware hit.
func TestNewComponentsAreNotMarkedAsRisk(t *testing.T) {
	inv := supply.Inventory{Artifacts: []supply.Artifact{
		{Kind: "ollama-model", ID: "ollama-model:registry.ollama.ai/library/gemma:4b",
			Name: "gemma:4b", Digest: strings.Repeat("a", 64)},
	}}
	r := &model.Report{}
	r.Add(model.Finding{ID: "SUP-012", Severity: model.Medium,
		Title:     "1 new component(s) installed since the baseline",
		Artifacts: []string{"ollama-model:registry.ollama.ai/library/gemma:4b"}})
	r.Finalize()
	control.Annotate(r)
	control.Inventory(r, inv)

	if len(r.Components) != 1 {
		t.Fatalf("components = %d", len(r.Components))
	}
	c := r.Components[0]
	if c.Flag != "" {
		t.Errorf("a newly installed model is flagged as a risk (%q)", c.Flag)
	}
	if c.State == "" {
		t.Error("a newly installed model carries no review marker at all")
	}
}

// A real risk finding still colours the row.
func TestRiskFindingsStillFlagTheirComponent(t *testing.T) {
	inv := supply.Inventory{Artifacts: []supply.Artifact{
		{Kind: "mcp-server", ID: "mcp-server:bad", Name: "bad", Digest: strings.Repeat("b", 64)},
	}}
	r := &model.Report{}
	r.Add(model.Finding{ID: "SUP-030", Severity: model.Critical,
		Title: "backdoored", Artifacts: []string{"mcp-server:bad"}})
	r.Finalize()
	control.Annotate(r)
	control.Inventory(r, inv)

	if r.Components[0].Flag != "CRITICAL" {
		t.Errorf("flag = %q, want CRITICAL", r.Components[0].Flag)
	}
}

// --hash-all exists so the 64 MB default is a choice the user can override,
// not a limit they are stuck behind.
func TestHashAllLiftsTheSizeCap(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	payload := realistic("a large poisoned checkpoint")
	big := filepath.Join(home, "big.bin")
	if err := os.WriteFile(big, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	index := indexContaining(t, payload)

	// Declared as larger than the cap, so the default run must skip it.
	weights := ModelInventory{Files: []WeightFile{{Path: big, Size: weightHashLimit + 1}}}

	capped := runSupply(t, home, SupplyOptions{HashDBPath: index, Weights: weights})
	if f := findingByID(capped, "SUP-050"); f != nil {
		t.Error("an oversize file was hashed without --hash-all")
	}

	full := runSupply(t, home, SupplyOptions{HashDBPath: index, Weights: weights, HashAll: true})
	if f := findingByID(full, "SUP-050"); f == nil {
		t.Error("--hash-all did not reach the oversize file")
	}
}

// A newly installed component is a review item. It should cost the grade far
// less than a real finding, and read as Low.
func TestNewComponentsAreLow(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("COMFYUI_PATH", filepath.Join(home, "ComfyUI"))

	node := filepath.Join(home, "ComfyUI", "custom_nodes", "a-node")
	if err := os.MkdirAll(node, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(node, "__init__.py"), realistic("print(1)"), 0o644); err != nil {
		t.Fatal(err)
	}
	baseline := filepath.Join(t.TempDir(), "baseline.json")

	// First run records the baseline.
	runSupply(t, home, SupplyOptions{BaselinePath: baseline, DisableHashDB: true})

	// A second node arrives.
	other := filepath.Join(home, "ComfyUI", "custom_nodes", "b-node")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "__init__.py"), realistic("print(2)"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := runSupply(t, home, SupplyOptions{BaselinePath: baseline, DisableHashDB: true})
	f := findingByID(r, "SUP-012")
	if f == nil {
		t.Fatal("a newly installed component produced no finding")
	}
	if f.Severity != model.Low {
		t.Errorf("severity = %v, want Low: installing something is usually deliberate", f.Severity)
	}
}

// A report that lists nothing must say where it looked, or "no components"
// reads as "no components exist" rather than "none were found here".
func TestReportSaysWhereItSearched(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", t.TempDir())
	t.Setenv("APPDATA", t.TempDir())
	t.Setenv("COMFYUI_PATH", "")

	r := runSupply(t, home, SupplyOptions{DisableHashDB: true})

	f := findingByID(r, "SUP-000")
	if f == nil {
		t.Fatal("no baseline finding")
	}
	if !strings.Contains(f.Detail, "COMFYUI_PATH") {
		t.Errorf("an empty inventory does not tell the reader how to widen the search:\n%s", f.Detail)
	}
}

// A hand-copied hashdb.bin that arrived without its meta.json has no build
// date and no source. Claiming it was "built locally" asserts provenance this
// machine does not have, and for a copied index it is simply false.
func TestIndexWithNoProvenanceSaysSo(t *testing.T) {
	if got := builtLabel(hashdb.Meta{}); got != "build date unknown" {
		t.Errorf("an index with no meta gave %q, want it to admit it does not know", got)
	}
	m := hashdb.Meta{Built: time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)}
	if got := builtLabel(m); got == "build date unknown" {
		t.Errorf("an index with a real build date gave %q", got)
	}
}
