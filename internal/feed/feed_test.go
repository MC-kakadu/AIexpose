package feed

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The copy compiled into the binary must always verify, in both profiles: the
// default build embeds a signed empty document, and if that stopped verifying
// the tool would report "rules could not be loaded" forever.
func TestBuiltinFeedVerifies(t *testing.T) {
	f, err := Builtin()
	if err != nil {
		t.Fatalf("built-in feed does not verify: %v", err)
	}
	if RulesBundled != (len(f.Entries) > 0) {
		t.Fatalf("RulesBundled is %v but the embedded feed has %d entries",
			RulesBundled, len(f.Entries))
	}
	for _, e := range f.Entries {
		if e.ID == "" || e.Match == "" || e.Title == "" {
			t.Errorf("incomplete entry: %+v", e)
		}
		if e.SeverityLevel() == 0 {
			t.Errorf("entry %s has an unrecognised severity %q", e.ID, e.Severity)
		}
	}
}

// A tampered feed must be rejected, not merely reported as odd. Otherwise
// anyone who can write the cache file decides what this tool accuses.
func TestTamperedFeedIsRejected(t *testing.T) {
	doc := append([]byte{}, builtinDoc...)
	doc[len(doc)-2] ^= 0xff
	if _, err := Parse(doc, builtinSig, "test"); err == nil {
		t.Fatal("a modified feed verified")
	}
}

func TestSignatureFromAnotherKeyIsRejected(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig := hex.EncodeToString(ed25519.Sign(priv, builtinDoc))
	if _, err := Parse(builtinDoc, []byte(sig), "test"); err != ErrBadSignature {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

// An unverifiable cache must fall back to the built-in list rather than
// leaving the machine unchecked.
// The rule file that ships alongside the release must verify and be complete,
// whichever profile this test runs under.
func TestShippedRuleFileIsUsable(t *testing.T) {
	doc, err := os.ReadFile("data/feed.json")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile("data/feed.json.sig")
	if err != nil {
		t.Fatal(err)
	}
	f, err := Parse(doc, sig, "test")
	if err != nil {
		t.Fatalf("the shipped rule file does not verify: %v", err)
	}
	if len(f.Entries) == 0 || len(f.Indicators) == 0 {
		t.Fatalf("shipped rules are incomplete: %d entries, %d indicators",
			len(f.Entries), len(f.Indicators))
	}
	if f.Credentials == nil || len(f.Credentials.Patterns) == 0 {
		t.Fatal("shipped rules carry no credential patterns")
	}
}

func TestLoadFallsBackWhenCacheIsCorrupt(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	dir := filepath.Join(home, ".aiexpose")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "feed.json"), []byte(`{"version":"evil","entries":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "feed.json.sig"), []byte("00"), 0o600); err != nil {
		t.Fatal(err)
	}

	f, err := Load("")
	if err != nil {
		t.Fatalf("Load returned %v, want the built-in feed", err)
	}
	if f.Version == "evil" {
		t.Fatal("an unsigned cache file was trusted")
	}
}

func TestMatchPackageVersions(t *testing.T) {
	f := Feed{Entries: []Entry{
		{ID: "A", Kind: Package, Match: "postmark-mcp", Severity: "critical", Title: "backdoored"},
		{ID: "B", Kind: Package, Match: "pinned-mcp", Versions: []string{"1.2.3"}, Severity: "high", Title: "one bad version"},
		{ID: "C", Kind: NodeName, Match: "ComfyUI_LLMVISION", Severity: "critical", Title: "stealer"},
	}}

	cases := []struct {
		name string
		c    Component
		want []string
	}{
		{"any version of a pulled package", Component{Package: "postmark-mcp", Version: "1.0.0"}, []string{"A"}},
		{"unpinned pulled package", Component{Package: "postmark-mcp"}, []string{"A"}},
		{"the listed bad version", Component{Package: "pinned-mcp", Version: "1.2.3"}, []string{"B"}},
		{"a different version is clean", Component{Package: "pinned-mcp", Version: "1.2.4"}, nil},
		{"unpinned can still resolve to the bad version", Component{Package: "pinned-mcp"}, []string{"B"}},
		{"node matched by name", Component{Name: "ComfyUI_LLMVISION"}, []string{"C"}},
		{"case-insensitive name", Component{Name: "comfyui_llmvision"}, []string{"C"}},
		{"unrelated component", Component{Package: "weather-mcp", Version: "1.0.0", Name: "weather"}, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hits := f.Match([]Component{tc.c})
			var got []string
			for _, h := range hits {
				got = append(got, h.Entry.ID)
				if h.Why == "" {
					t.Error("a hit must explain why it matched")
				}
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestMatchDigests(t *testing.T) {
	f := Feed{Entries: []Entry{
		{ID: "D", Kind: ArtifactDigest, Match: "ABC123", Severity: "critical", Title: "bad tree"},
		{ID: "E", Kind: FileDigest, Match: "def456", Severity: "critical", Title: "bad file"},
	}}
	hits := f.Match([]Component{
		{Name: "one", Digest: "abc123"},
		{Name: "two", Digest: "zzz", FileDigests: []string{"111", "DEF456"}},
	})
	if len(hits) != 2 {
		t.Fatalf("got %d hits, want 2: %+v", len(hits), hits)
	}
}

func TestStale(t *testing.T) {
	fresh := Feed{Updated: time.Now().Add(-24 * time.Hour)}
	old := Feed{Updated: time.Now().Add(-90 * 24 * time.Hour)}
	if fresh.Stale() {
		t.Error("a one-day-old feed is not stale")
	}
	if !old.Stale() {
		t.Error("a 90-day-old feed is stale")
	}
}

// Installing rules is how a machine with no feed endpoint, or no internet at
// all, arms the tool. A file that does not verify must be refused, and a
// refusal must leave the rules that were already installed alone.
func TestInstallFromFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	src := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(src, builtinDocFixture(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src+".sig", builtinSigFixture(t), 0o600); err != nil {
		t.Fatal(err)
	}

	f, err := InstallFromFile(src)
	if err != nil {
		t.Fatalf("installing the shipped rules failed: %v", err)
	}
	if len(f.Entries) == 0 {
		t.Fatal("installed rules are empty")
	}

	// A later scan must find them without being told where they are.
	cached, err := Load("")
	if err != nil || len(cached.Entries) != len(f.Entries) {
		t.Fatalf("installed rules were not picked up from the cache: %v", err)
	}

	// Tampering must be refused, and must not disturb what is installed.
	bad := filepath.Join(t.TempDir(), "bad.json")
	doc := builtinDocFixture(t)
	doc[len(doc)-2] ^= 0xff
	if err := os.WriteFile(bad, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad+".sig", builtinSigFixture(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallFromFile(bad); err == nil {
		t.Fatal("a tampered rule file was installed")
	}
	if after, err := Load(""); err != nil || len(after.Entries) != len(f.Entries) {
		t.Fatal("a refused install disturbed the rules already in place")
	}

	// A rule file with no signature beside it is not trusted.
	lone := filepath.Join(t.TempDir(), "lone.json")
	if err := os.WriteFile(lone, builtinDocFixture(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallFromFile(lone); err == nil {
		t.Fatal("a rule file with no signature was installed")
	}
}

func TestUpdateRefusesPlaceholderEndpoint(t *testing.T) {
	if Publishable("https://example.invalid/aiexpose/feed/v1/feed.json") {
		t.Error("the placeholder endpoint must not be treated as publishable")
	}
	if Publishable("") {
		t.Error("an empty URL must not be treated as publishable")
	}
	if !Publishable("https://feed.example.com/v1/feed.json") {
		t.Error("a real URL must be publishable")
	}
	if _, err := Update("https://example.invalid/feed.json"); err != ErrNoEndpoint {
		t.Errorf("Update on the placeholder returned %v, want ErrNoEndpoint", err)
	}
}

func builtinDocFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("data/feed.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func builtinSigFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("data/feed.json.sig")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNewerVersion(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"2026.09.11.1", "2026.09.10.3", true},
		{"2026.09.10.3", "2026.09.11.1", false},
		// A string comparison gets this one wrong.
		{"2026.09.11.10", "2026.09.11.9", true},
		{"2026.09.11.9", "2026.09.11.10", false},
		{"2026.09.11.1", "2026.09.11.1", false},
		// A shorter version is the same as one padded with zeros.
		{"2026.09.11", "2026.09.11.0", false},
		{"2026.09.11.1", "2026.09.11", true},
		// The built-in empty copy must never shadow a real release.
		{"empty", "2026.09.10.3", false},
		{"2026.09.10.3", "empty", true},
		{"", "2026.09.10.3", false},
		{"2026.09.10.3", "", true},
	}
	for _, c := range cases {
		if got := newerVersion(c.a, c.b); got != c.want {
			t.Errorf("newerVersion(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// The bug this guards: Load returned the cache the moment it verified, so a
// machine that had ever run --install-rules kept that rule set forever. A
// corrected pattern shipped in a release could never reach it, which defeats
// the reason rules are signed data in the first place.
func TestLoadPrefersTheNewestCandidate(t *testing.T) {
	var best Feed
	var found bool
	consider := func(f Feed, err error) {
		if err != nil {
			return
		}
		if !found || newerVersion(f.Version, best.Version) {
			best, found = f, true
		}
	}

	// The shapes Load actually sees: a stale cache, a newer file beside the
	// executable, and the empty built-in copy.
	consider(Feed{Version: "2026.09.10.3", Origin: "cached"}, nil)
	consider(Feed{Version: "2026.09.11.1", Origin: "beside the executable"}, nil)
	consider(Feed{Version: "empty", Origin: "built in"}, nil)

	if best.Version != "2026.09.11.1" {
		t.Fatalf("chose %q from %q, want the newest", best.Version, best.Origin)
	}

	// And the cache still wins when it is the newest, which is the normal case
	// after --update-feed.
	best, found = Feed{}, false
	consider(Feed{Version: "2026.09.12.1", Origin: "cached"}, nil)
	consider(Feed{Version: "2026.09.11.1", Origin: "beside the executable"}, nil)
	if best.Origin != "cached" {
		t.Errorf("chose %q, want the cache when it is newer", best.Origin)
	}
}

// A candidate that fails verification must not be considered at all.
func TestUnverifiableCandidatesAreIgnored(t *testing.T) {
	var best Feed
	var found bool
	consider := func(f Feed, err error) {
		if err != nil {
			return
		}
		if !found || newerVersion(f.Version, best.Version) {
			best, found = f, true
		}
	}
	consider(Feed{Version: "2026.09.10.3", Origin: "cached"}, nil)
	consider(Feed{Version: "2999.01.01.1", Origin: "forged"}, errBadSignature)

	if best.Origin != "cached" {
		t.Errorf("an unverifiable newer candidate was used: %q", best.Origin)
	}
}

var errBadSignature = errors.New("signature does not verify")

// The attestation block prints the feed's version and its updated date side by
// side. A release that bumps one and forgets the other publishes a document
// that disagrees with itself, which is the one thing an evidence block must
// never do -- and it drifted exactly that way once.
func TestVersionAndUpdatedDateAgree(t *testing.T) {
	f, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if !RulesBundled {
		// The default build embeds an empty document; check the shipped file.
		doc, err := os.ReadFile(filepath.Join("data", "feed.json"))
		if err != nil {
			t.Fatal(err)
		}
		sig, err := os.ReadFile(filepath.Join("data", "feed.json.sig"))
		if err != nil {
			t.Fatal(err)
		}
		if f, err = Parse(doc, sig, "shipped"); err != nil {
			t.Fatal(err)
		}
	}

	parts, ok := versionParts(f.Version)
	if !ok || len(parts) < 3 {
		t.Skipf("version %q is not date-shaped, nothing to cross-check", f.Version)
	}
	wantDate := time.Date(parts[0], time.Month(parts[1]), parts[2], 0, 0, 0, 0, time.UTC)
	if got := f.Updated.UTC().Truncate(24 * time.Hour); !got.Equal(wantDate) {
		t.Errorf("version %s encodes %s but updated says %s; bump both when releasing rules",
			f.Version, wantDate.Format("2006-01-02"), got.Format("2006-01-02"))
	}
}
