package feed

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	fetchTimeout = 20 * time.Second
	maxFeedBytes = 8 << 20
)

// Publishable reports whether a feed URL is a real endpoint. Until one is
// published, the source field carries a deliberate placeholder, and failing
// with a DNS error would tell the user nothing useful.
func Publishable(url string) bool {
	return url != "" && !strings.Contains(url, "example.invalid")
}

type noEndpointErr struct{}

func (noEndpointErr) Error() string {
	return "no rule endpoint is published yet, so there is nothing to download.\n" +
		"Install the rule file that shipped with this release instead:\n" +
		"  aiexpose --install-rules aiexpose-rules.json\n" +
		"If you built from source, the same signed file is in the tree you built from:\n" +
		"  aiexpose --install-rules internal/feed/data/feed.json\n" +
		"It only has to be done once; later scans pick the rules up on their own."
}

// ErrNoEndpoint means the build has no real feed URL to fetch from.
var ErrNoEndpoint error = noEndpointErr{}

var errNoEndpoint = ErrNoEndpoint

// InstallFromFile verifies a signed rule file and installs it into the cache,
// so every later scan finds it without being told where it is.
//
// This is the path that works on a machine with no feed endpoint to fetch from,
// and on one with no internet access at all: copy two files across, run this
// once, and the tool is armed from then on.
func InstallFromFile(path string) (Feed, error) {
	doc, err := os.ReadFile(path)
	if err != nil {
		return Feed{}, err
	}
	sig, err := os.ReadFile(path + ".sig")
	if err != nil {
		return Feed{}, fmt.Errorf("no signature beside the rule file: %w\n"+
			"A rule file is only trusted with its .sig alongside it, so copy both across", err)
	}
	f, err := Parse(doc, sig, "installed from "+path)
	if err != nil {
		return Feed{}, fmt.Errorf("the rule file was rejected: %w", err)
	}
	if err := cache(doc, sig); err != nil {
		return f, err
	}
	return f, nil
}

// cache writes a verified feed to the location every scan reads.
func cache(doc, sig []byte) error {
	if err := os.MkdirAll(CacheDir(), 0o700); err != nil {
		return fmt.Errorf("rules verified but could not be stored: %w", err)
	}
	docPath, sigPath := cachePaths()
	if err := writeAtomic(docPath, doc); err != nil {
		return fmt.Errorf("rules verified but could not be stored: %w", err)
	}
	if err := writeAtomic(sigPath, sig); err != nil {
		return fmt.Errorf("rules verified but their signature could not be stored: %w", err)
	}
	return nil
}

// Update fetches a signed feed and caches it, but only after the signature
// verifies. A feed that does not verify is discarded and the previous copy is
// left in place.
//
// This is the only part of aiexpose that touches the network, it never runs
// during a normal scan, and the request carries nothing about this machine:
// no query string, no identifier, no report of what is installed.
func Update(url string) (Feed, error) {
	if !Publishable(url) {
		return Feed{}, errNoEndpoint
	}
	doc, err := fetch(url)
	if err != nil {
		return Feed{}, err
	}
	sig, err := fetch(url + ".sig")
	if err != nil {
		return Feed{}, fmt.Errorf("feed downloaded but its signature could not be fetched: %w", err)
	}

	f, err := Parse(doc, sig, "downloaded from "+url)
	if err != nil {
		return Feed{}, fmt.Errorf("downloaded feed was rejected: %w", err)
	}

	return f, cache(doc, sig)
}

func fetch(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "aiexpose/feed-update")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes))
}

func writeAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Clean(path))
}
