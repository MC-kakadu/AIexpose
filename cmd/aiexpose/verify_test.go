package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Someone who cloned the repository and built the binary has no SHA256SUMS:
// it is published with a release, not kept in the tree. A bare "no such file"
// sends them looking for a bug in a situation where nothing is wrong.
func TestMissingChecksumFileExplainsItself(t *testing.T) {
	dir := t.TempDir()
	stderr := captureStderr(t, func() {
		if code := verifySelf(filepath.Join(dir, "SHA256SUMS")); code != 2 {
			t.Errorf("exit code = %d, want 2", code)
		}
	})
	for _, want := range []string{"published with each release", "built", "sha256 "} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the message does not mention %q:\n%s", want, stderr)
		}
	}
	if strings.Contains(stderr, "no such file or directory") {
		t.Error("the raw OS error is still shown")
	}
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				b.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- b.String()
	}()
	fn()
	w.Close()
	os.Stderr = old
	return <-done
}
