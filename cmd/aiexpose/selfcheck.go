package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// selfDigest returns the SHA-256 of the running executable.
//
// Endpoint protection quarantines unsigned security tools regularly, and the
// first question after that happens is whether the file was tampered with or
// merely flagged. Being able to print your own hash, and check it against the
// published checksums, answers that without trusting anything else.
func selfDigest() (string, string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", "", err
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	f, err := os.Open(path)
	if err != nil {
		return "", path, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", path, err
	}
	return hex.EncodeToString(h.Sum(nil)), path, nil
}

// verifySelf checks the running executable against a published SHA256SUMS file.
// Exit codes: 0 matched, 1 not listed or mismatched, 2 could not check.
func verifySelf(sumsPath string) int {
	digest, path, err := selfDigest()
	if err != nil {
		fmt.Fprintln(os.Stderr, "aiexpose: could not hash this executable:", err)
		return 2
	}
	f, err := os.Open(sumsPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "aiexpose:", err)
		return 2
	}
	defer f.Close()

	want := filepath.Base(path)
	var listed []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		sum, name := fields[0], strings.TrimPrefix(fields[len(fields)-1], "*")
		listed = append(listed, name)
		if !strings.EqualFold(sum, digest) {
			continue
		}
		fmt.Printf("This executable matches %s in %s.\n", name, sumsPath)
		if !strings.EqualFold(name, want) {
			fmt.Printf("It has been renamed from %s to %s, which is fine.\n", name, want)
		}
		fmt.Printf("sha256 %s\n", digest)
		return 0
	}

	fmt.Fprintf(os.Stderr, "This executable does NOT match any entry in %s.\n", sumsPath)
	fmt.Fprintf(os.Stderr, "  running:  %s\n  sha256:   %s\n  file has: %s\n",
		path, digest, strings.Join(listed, ", "))
	fmt.Fprintln(os.Stderr, "\nEither this is a different build, or the file was modified. "+
		"Download it again, or rebuild from source: the release build is reproducible, "+
		"so building the same tag with the same Go version produces this exact hash.")
	return 1
}
