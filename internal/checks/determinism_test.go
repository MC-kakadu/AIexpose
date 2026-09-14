package checks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MC-kakadu/AIexpose/internal/control"
	"github.com/MC-kakadu/AIexpose/internal/model"
)

// Two scans of a machine that has not changed must produce the same report.
//
// This is not a nicety for a tool whose whole proposition is telling people
// what changed. A report that reorders itself between runs produces a diff when
// nothing happened, and a reader who sees phantom diffs learns to skip the real
// ones. It broke exactly that way: the pickle evidence list sorted on size
// alone, over a map, so two files of equal size traded places every run.
func TestTwoScansOfAnUnchangedMachineAgree(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
	t.Setenv("COMFYUI_PATH", filepath.Join(home, "ComfyUI"))

	// Several files of identical size, which is what makes a partial sort key
	// visible. Same-named nodes in two installs do the same for the component
	// table.
	cache := filepath.Join(home, ".cache", "torch", "hub", "checkpoints")
	if err := os.MkdirAll(cache, 0o755); err != nil {
		t.Fatal(err)
	}
	same := make([]byte, 4096)
	for _, n := range []string{"alpha.pth", "bravo.pth", "charlie.pth", "delta.pt", "echo.bin"} {
		if err := os.WriteFile(filepath.Join(cache, n), same, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, install := range []string{"first", "second"} {
		d := filepath.Join(home, "AppData", "Local", "Comfy-Desktop",
			"ComfyUI-Installs", install, "ComfyUI", "custom_nodes", "shared-name")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "__init__.py"),
			[]byte("import torch  # "+install+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	baseline := filepath.Join(t.TempDir(), "baseline.json")
	scan := func() string {
		r := &model.Report{}
		weights := ModelFormats(r)
		SupplyChain(r, SupplyOptions{
			BaselinePath: baseline, DisableFeed: true, DisableHashDB: true, Weights: weights,
		})
		r.Finalize()
		control.Annotate(r)
		control.Inventory(r, SupplyChainInventory(r, baseline))

		// Everything except the clock, which is expected to differ.
		b, err := json.Marshal(struct {
			Findings   []model.Finding
			Components []model.Component
			Coverage   []model.ControlCoverage
		}{r.Findings, r.Components, r.Coverage})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	// The very first scan records the baseline and reports that; every later
	// one compares against it. Warm it up so the runs being compared are the
	// same kind of run.
	scan()

	first := scan()
	for i := 0; i < 8; i++ {
		if got := scan(); got != first {
			t.Fatalf("scan %d differs from the first with nothing changed on disk\n first: %s\n  got: %s",
				i+2, firstDiff(first, got), firstDiff(got, first))
		}
	}
}

// firstDiff trims two strings to the neighbourhood of their first difference,
// because a whole report is unreadable in a failure message.
func firstDiff(a, b string) string {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	start := n - 60
	if start < 0 {
		start = 0
	}
	end := n + 60
	if end > len(a) {
		end = len(a)
	}
	return "..." + strings.TrimSpace(a[start:end]) + "..."
}
