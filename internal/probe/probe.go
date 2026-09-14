// Package probe identifies services by talking to them over loopback only.
// Nothing in this package ever contacts a remote host.
package probe

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MC-kakadu/AIexpose/internal/catalog"
	"github.com/MC-kakadu/AIexpose/internal/model"
	"github.com/MC-kakadu/AIexpose/internal/netstat"
)

const (
	dialTimeout = 900 * time.Millisecond
	readLimit   = 64 << 10
	maxParallel = 12
)

func client() *http.Client {
	return &http.Client{
		Timeout: 2500 * time.Millisecond,
		Transport: &http.Transport{
			DialContext:         (&net.Dialer{Timeout: dialTimeout}).DialContext,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // loopback self-signed certs
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: dialTimeout,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Identify turns raw listeners into recognised services.
func Identify(listeners []model.Listener) []model.Service {
	idx := catalog.PortIndex()
	c := client()

	var (
		mu   sync.Mutex
		out  []model.Service
		wg   sync.WaitGroup
		sem  = make(chan struct{}, maxParallel)
		seen = map[string]bool{}
	)

	for _, l := range listeners {
		candidates := idx[l.Port]
		if hinted := byProcess(l); hinted != nil {
			candidates = append(candidates, *hinted)
		}
		if len(candidates) == 0 {
			continue
		}
		wg.Add(1)
		go func(l model.Listener, cands []catalog.Signature) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			svc, ok := identifyOne(c, l, cands)
			if !ok || isNoise(svc) {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			key := svc.Name + "@" + strconv.Itoa(l.Port) + "/" + l.Addr
			if seen[key] {
				return
			}
			seen[key] = true
			out = append(out, svc)
		}(l, candidates)
	}
	wg.Wait()
	return out
}

func identifyOne(c *http.Client, l model.Listener, cands []catalog.Signature) (model.Service, bool) {
	target := probeHost(l)

	var best catalog.Signature
	var confirmed bool
	var evidence string

	for _, sig := range cands {
		if sig.FingerprintPath == "" {
			continue
		}
		body, status, ok := fetch(c, target, sig.FingerprintPath)
		if !ok || status >= 400 {
			continue
		}
		if matches(body, sig.FingerprintBody) {
			best, confirmed = sig, true
			evidence = sig.FingerprintPath + " -> " + strconv.Itoa(status)
			break
		}
	}

	if !confirmed {
		// Fall back to the process-name hint, or the single port claimant.
		if h := byProcess(l); h != nil {
			best = *h
		} else if len(cands) == 1 {
			best = cands[0]
		} else {
			return model.Service{}, false
		}
	}

	svc := model.Service{
		Name:      best.Name,
		Kind:      best.Kind,
		Listener:  l,
		Exposure:  netstat.Classify(l.Addr),
		Confirmed: confirmed,
		Evidence:  evidence,
	}

	if best.AuthPath != "" {
		if body, status, ok := fetch(c, target, best.AuthPath); ok && status >= 200 && status < 300 {
			if matches(body, best.AuthBody) {
				svc.NoAuth = true
			}
		}
	}
	return svc, true
}

// dynamicPortFloor is where Windows and Linux both start handing out ephemeral
// ports. A desktop app's helper process picks one of these on every launch.
const dynamicPortFloor = 49152

// isNoise drops a guess that is almost certainly a helper process rather than a
// service the user runs. A GUI app such as "ollama app.exe" listens on a fresh
// ephemeral port each time it starts; matching it on process name alone reports
// the same product twice and asks the user to act on a port that will not exist
// tomorrow. A real service on a high port still passes, because the HTTP
// fingerprint confirms it.
func isNoise(s model.Service) bool {
	return !s.Confirmed && s.Listener.Port >= dynamicPortFloor
}

// probeHost always resolves to loopback so that identification never leaves
// the machine, even when the service is bound to 0.0.0.0.
func probeHost(l model.Listener) string {
	if l.IPv6 {
		return "[::1]:" + strconv.Itoa(l.Port)
	}
	return "127.0.0.1:" + strconv.Itoa(l.Port)
}

func fetch(c *http.Client, hostPort, path string) (string, int, bool) {
	for _, scheme := range []string{"http", "https"} {
		ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+hostPort+path, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "aiexpose/local-check")
		resp, err := c.Do(req)
		if err != nil {
			cancel()
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, readLimit))
		resp.Body.Close()
		cancel()
		return string(b), resp.StatusCode, true
	}
	return "", 0, false
}

func matches(body string, needles []string) bool {
	if len(needles) == 0 {
		return true
	}
	for _, n := range needles {
		if strings.Contains(body, n) {
			return true
		}
	}
	return false
}

func byProcess(l model.Listener) *catalog.Signature {
	if l.Process == "" {
		return nil
	}
	p := strings.ToLower(l.Process)
	for i := range catalog.Signatures {
		for _, hint := range catalog.Signatures[i].ProcHints {
			if strings.Contains(p, hint) {
				return &catalog.Signatures[i]
			}
		}
	}
	return nil
}
