// Package feed holds the list of components already known to be malicious.
//
// Pattern matching catches behaviour that is visible in source. It is defeated
// by obfuscation, and it cannot know that a specific published version of an
// otherwise ordinary package was backdoored. A curated list of known-bad
// components covers exactly that gap, and unlike a scanner it cannot be cloned
// in an afternoon: the value is in keeping it current.
package feed

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/MC-kakadu/AIexpose/internal/model"
)

// Kind is how an entry is matched against what is installed.
type Kind string

const (
	// Package matches an MCP server launched from a named registry package.
	Package Kind = "package"
	// ArtifactDigest matches the digest of a whole component directory.
	ArtifactDigest Kind = "artifact-digest"
	// FileDigest matches one file inside a component.
	FileDigest Kind = "file-digest"
	// NodeName matches a component by directory name. Names collide, so an
	// entry of this kind never carries more than moderate severity on its own.
	NodeName Kind = "node-name"
)

// Entry is one known-bad component.
type Entry struct {
	ID    string `json:"id"`
	Kind  Kind   `json:"kind"`
	Match string `json:"match"`
	// Versions lists exact affected releases. Ranges expresses the same thing
	// the way advisories usually state it, with an introduced and a fixed
	// bound. Both empty means every published version is affected, which is
	// correct for a package that was removed from its registry rather than
	// patched -- and wrong, dangerously, for a legitimate package that was
	// briefly hijacked. See Validate.
	Versions []string `json:"versions,omitempty"`
	Ranges   []Range  `json:"version_ranges,omitempty"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail,omitempty"`
	Ref      string   `json:"reference,omitempty"`
	Added    string   `json:"added,omitempty"`
}

// IndicatorRule is a pattern describing behaviour no workflow node or agent
// skill has a legitimate reason to perform.
//
// These live in the signed feed rather than in compiled string literals for two
// reasons. New patterns reach users without shipping a binary, and the strings
// themselves -- browser credential paths, webhook endpoints, wallet filenames --
// are exactly the string table an infostealer carries, so keeping them in a
// signed data file rather than in the executable stops endpoint protection from
// quarantining the tool on sight.
type IndicatorRule struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Pattern  string `json:"pattern"`
}

// SeverityLevel maps the rule's label onto the report's scale.
func (r IndicatorRule) SeverityLevel() model.Severity {
	return Entry{Severity: r.Severity}.SeverityLevel()
}

// CredentialPattern recognises one vendor's API key.
type CredentialPattern struct {
	ID      string `json:"id"`
	Vendor  string `json:"vendor"`
	Pattern string `json:"pattern"`
}

// Credentials describes what a plaintext key looks like and where people leave
// them. Order matters: more specific prefixes must come first, because sk-ant-
// also satisfies the broader OpenAI rule.
type Credentials struct {
	Patterns     []CredentialPattern `json:"patterns"`
	HistoryFiles []string            `json:"history_files"`
	ConfigFiles  []string            `json:"config_files"`
	SearchDirs   []string            `json:"search_dirs"`
	SearchNames  []string            `json:"search_names"`

	// SearchExts turns the search from "open these exact filenames" into
	// "read any text file of these kinds". People keep keys in keys.txt and
	// in notes.md far more often than in a file named .env, and an exact-name
	// list can never cover a name someone made up.
	SearchExts []string `json:"search_exts,omitempty"`

	// DocDirs are the personal document folders searched only when the user
	// asks with --scan-docs. They are opt-in for the same reason shell
	// history is: walking someone's Desktop reading every text file is the
	// defining behaviour of an information stealer, and a scanner that does
	// it unasked deserves to be quarantined.
	DocDirs []string `json:"doc_dirs,omitempty"`

	// SkipDirs are never descended into, anywhere. Dependency and cache trees
	// hold thousands of files and no credential the user wrote down.
	SkipDirs []string `json:"skip_dirs,omitempty"`
}

// Feed is the signed document.
type Feed struct {
	Version     string          `json:"version"`
	Updated     time.Time       `json:"updated"`
	Source      string          `json:"source,omitempty"`
	Entries     []Entry         `json:"entries"`
	Indicators  []IndicatorRule `json:"indicators,omitempty"`
	Credentials *Credentials    `json:"credentials,omitempty"`

	// Origin describes where this copy came from, for the report.
	Origin string `json:"-"`
}

// ErrBadSignature means the feed did not verify against the built-in key.
var ErrBadSignature = errors.New("feed signature does not verify")

// StaleAfter is how old a cached feed may be before the report says so.
const StaleAfter = 45 * 24 * time.Hour

// Severity maps the feed's label onto the report's scale.
func (e Entry) SeverityLevel() model.Severity {
	switch strings.ToLower(e.Severity) {
	case "critical":
		return model.Critical
	case "high":
		return model.High
	case "medium":
		return model.Medium
	case "low":
		return model.Low
	}
	return model.Info
}

// Age is how long ago the feed was published.
func (f Feed) Age() time.Duration { return time.Since(f.Updated) }

// Stale reports whether this copy is old enough to mention.
func (f Feed) Stale() bool { return f.Age() > StaleAfter }

// Verify checks a detached signature against the compiled-in public key.
//
// The feed decides whether the tool accuses a component of being malware, so it
// is a trust-critical input. Without a signature, anyone who can serve or write
// the cache file could silence the scanner or make it accuse innocent packages.
func Verify(document, signature []byte) error {
	sig, err := hex.DecodeString(strings.TrimSpace(string(signature)))
	if err != nil {
		return fmt.Errorf("signature is not valid hex: %w", err)
	}
	key, err := hex.DecodeString(PublicKeyHex)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("the built-in public key is unusable")
	}
	if !ed25519.Verify(ed25519.PublicKey(key), document, sig) {
		return ErrBadSignature
	}
	return nil
}

// Parse validates and decodes a signed feed.
func Parse(document, signature []byte, origin string) (Feed, error) {
	if err := Verify(document, signature); err != nil {
		return Feed{}, err
	}
	var f Feed
	if err := json.Unmarshal(document, &f); err != nil {
		return Feed{}, fmt.Errorf("feed is not readable: %w", err)
	}
	f.Origin = origin
	return f, nil
}

// CacheDir is where an updated feed is stored.
func CacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, ".aiexpose")
}

func cachePaths() (doc, sig string) {
	d := CacheDir()
	return filepath.Join(d, "feed.json"), filepath.Join(d, "feed.json.sig")
}

// Load returns the newest feed available: an explicit file if one is given,
// otherwise the updated cache, otherwise the copy built into the binary.
// A cached feed that fails verification is ignored rather than trusted.
func Load(explicitPath string) (Feed, error) {
	if explicitPath != "" {
		doc, err := os.ReadFile(explicitPath)
		if err != nil {
			return Feed{}, err
		}
		sig, err := os.ReadFile(explicitPath + ".sig")
		if err != nil {
			return Feed{}, fmt.Errorf("no signature file at %s.sig: %w", explicitPath, err)
		}
		return Parse(doc, sig, explicitPath)
	}

	// Every source that verifies is a candidate, and the newest one wins.
	//
	// This used to return the cache the moment it verified. That made a rule
	// fix undeliverable: a machine that had ever run --install-rules kept that
	// version forever, because nothing compared it against anything. Rules are
	// separated out as signed data precisely so a bad pattern can be corrected
	// without a new binary, and a cache that shadows every later release
	// throws that away. Every candidate is still signature-checked against the
	// key compiled into this binary, so preferring a newer file is not a way
	// in for anyone.
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

	consider(loadCache())
	consider(loadBesideExecutable())
	consider(Builtin())

	if !found {
		return Builtin()
	}
	return best, nil
}

// loadCache reads the copy that --update-feed and --install-rules write.
func loadCache() (Feed, error) {
	docPath, sigPath := cachePaths()
	doc, err := os.ReadFile(docPath)
	if err != nil {
		return Feed{}, err
	}
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return Feed{}, err
	}
	return Parse(doc, sig, "cached, updated "+shortDate(doc))
}

// besideExecutableName is the rule file a release ships next to the binary.
const besideExecutableName = "aiexpose-rules.json"

// loadBesideExecutable reads a signed rule file sitting next to the program.
//
// It is how a corrected rule set reaches someone who just downloaded a release
// and never ran an install command: the file is already in the folder they
// unzipped. It is only trusted because it still has to verify against the
// public key compiled in here, so dropping a file beside the binary grants
// nothing that forging a signature would not already require.
func loadBesideExecutable() (Feed, error) {
	exe, err := os.Executable()
	if err != nil {
		return Feed{}, err
	}
	path := filepath.Join(filepath.Dir(exe), besideExecutableName)
	doc, err := os.ReadFile(path)
	if err != nil {
		return Feed{}, err
	}
	sig, err := os.ReadFile(path + ".sig")
	if err != nil {
		return Feed{}, err
	}
	return Parse(doc, sig, "shipped beside the executable, updated "+shortDate(doc))
}

// newerVersion compares two dotted numeric feed versions such as 2026.09.11.1.
//
// Segments are compared as numbers, so 2026.09.11.10 is newer than
// 2026.09.11.9 -- which a string comparison gets wrong. A version that is not
// in that shape (the empty built-in copy says "empty") sorts oldest, so it can
// never shadow a real release.
func newerVersion(a, b string) bool {
	as, aok := versionParts(a)
	bs, bok := versionParts(b)
	switch {
	case !aok:
		return false
	case !bok:
		return true
	}
	for i := 0; i < len(as) || i < len(bs); i++ {
		av, bv := 0, 0
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		if av != bv {
			return av > bv
		}
	}
	return false
}

func versionParts(v string) ([]int, bool) {
	if v == "" {
		return nil, false
	}
	fields := strings.Split(v, ".")
	out := make([]int, 0, len(fields))
	for _, f := range fields {
		n, err := strconv.Atoi(f)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

func shortDate(doc []byte) string {
	var probe struct {
		Updated time.Time `json:"updated"`
	}
	if err := json.Unmarshal(doc, &probe); err == nil && !probe.Updated.IsZero() {
		return probe.Updated.Format("2006-01-02")
	}
	return "unknown date"
}

// Builtin returns the copy compiled into this binary. It is what a machine that
// has never fetched an update runs against, so it must always verify.
func Builtin() (Feed, error) {
	origin := "built into this binary"
	if !RulesBundled {
		origin = "built into this binary (no rules until --update-feed or --feed)"
	}
	return Parse(builtinDoc, builtinSig, origin)
}
