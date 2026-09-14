package checks

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/MC-kakadu/AIexpose/internal/model"
)

// pickleExts load through Python's pickle module, which executes arbitrary
// code contained in the file the moment the weights are read.
var pickleExts = map[string]bool{
	".ckpt": true, ".pt": true, ".pth": true, ".bin": true, ".pkl": true,
}

// safeExts are pure tensor containers with no code execution path.
var safeExts = map[string]bool{
	".safetensors": true, ".gguf": true, ".ggml": true, ".onnx": true,
}

// modelRoot is a place weights live, and whether the tool that owns it put them
// there itself.
type modelRoot struct {
	rel string
	// absolute marks rel as a full path rather than one relative to home.
	absolute bool
	// managed marks a cache a framework fills from its own hub. The user does
	// not choose what lands there file by file, and nothing arrives without a
	// library asking for it by name.
	managed bool
}

var modelRoots = []modelRoot{
	{rel: filepath.Join(".ollama", "models"), managed: true},
	{rel: filepath.Join(".cache", "huggingface", "hub"), managed: true},
	{rel: filepath.Join(".cache", "torch", "hub"), managed: true},
	{rel: filepath.Join(".cache", "lm-studio", "models"), managed: true},
	{rel: filepath.Join(".lmstudio", "models"), managed: true},
	{rel: filepath.Join("ComfyUI", "models")},
	{rel: filepath.Join("ComfyUI_windows_portable", "ComfyUI", "models")},
	{rel: filepath.Join("comfyui", "models")},
	{rel: filepath.Join("Documents", "ComfyUI", "models")},
	{rel: filepath.Join("stable-diffusion-webui", "models")},
	{rel: filepath.Join("text-generation-webui", "models")},
	{rel: "models"},
}

const (
	walkBudget   = 8 * time.Second
	maxWalkFiles = 200000
)

// cacheBookkeeping are directories a framework fills with its own records
// rather than with weights. Walking them produces files that look like models
// and are not.
//
// The one that matters is Hugging Face's .no_exist: it holds an EMPTY file
// named after every optional file the library confirmed is absent upstream, so
// the next load skips the HTTP request. Counting those as model files inflates
// every total, and hashing them is worse -- every one of them has the MD5 of
// the empty string, which a general malware corpus contains.
var cacheBookkeeping = map[string]bool{
	".no_exist": true, ".locks": true, "refs": true, "trees": true,
}

// WeightFile is one model file found on disk, with the size needed to decide
// whether hashing it is affordable.
type WeightFile struct {
	Path string
	Size int64
}

// ModelInventory is what the format walk found, handed on so that later checks
// do not walk the same gigabytes again.
type ModelInventory struct {
	Files []WeightFile
}

// desktopModelRoots are where the ComfyUI Desktop app keeps weights: a shared
// library outside any single install, plus a models folder inside each one.
// None of it sits under the home directory, which is why a machine with the
// desktop app reported no ComfyUI at all until this was added.
func desktopModelRoots(home string) []string {
	var out []string
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		out = append(out, filepath.Join(local, "Comfy-Desktop", "ComfyUI-Shared", "models"))
	}
	for _, base := range []string{
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Comfy-Desktop", "ComfyUI-Installs"),
		filepath.Join(home, "ComfyUI-Installs"),
		filepath.Join(home, "ComfyUI-Shared"),
	} {
		if base == "" {
			continue
		}
		entries, err := os.ReadDir(base)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			out = append(out,
				filepath.Join(base, e.Name(), "ComfyUI", "models"),
				filepath.Join(base, e.Name(), "models"))
		}
	}
	return out
}

// ModelFormats inventories weight files by container format. Pickle-based
// weights are the delivery mechanism behind the malicious models repeatedly
// found on public model hubs.
//
// It returns every weight file it saw. The malware hash check needs exactly
// this list, and these directories hold gigabytes: walking them twice would be
// the most expensive thing this scan does.
func ModelFormats(r *model.Report) ModelInventory {
	var inv ModelInventory
	home, err := os.UserHomeDir()
	if err != nil {
		return inv
	}

	deadline := time.Now().Add(walkBudget)
	managed := map[string]int64{}
	chosen := map[string]int64{}
	var safeCount, pickleCount, scanned int

	roots := make([]modelRoot, 0, len(modelRoots)+4)
	roots = append(roots, modelRoots...)
	for _, abs := range desktopModelRoots(home) {
		// A weight in a ComfyUI models folder was put there by a person, so it
		// is treated the same as one in any other ComfyUI install.
		roots = append(roots, modelRoot{rel: abs, managed: false, absolute: true})
	}

	for _, root := range roots {
		pickles := chosen
		if root.managed {
			pickles = managed
		}
		dir := filepath.Join(home, root.rel)
		if root.absolute {
			dir = root.rel
		}
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			continue
		}
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil //nolint:nilerr // unreadable subtrees are skipped
			}
			if scanned > maxWalkFiles || time.Now().After(deadline) {
				return filepath.SkipAll
			}
			if d.IsDir() {
				if cacheBookkeeping[strings.ToLower(d.Name())] {
					return filepath.SkipDir
				}
				return nil
			}
			scanned++
			ext := strings.ToLower(filepath.Ext(path))
			if pickleExts[ext] || safeExts[ext] {
				size := int64(-1)
				if info, err := os.Stat(path); err == nil {
					size = info.Size()
				}
				inv.Files = append(inv.Files, WeightFile{Path: path, Size: size})
			}
			switch {
			case pickleExts[ext]:
				pickleCount++
				// os.Stat follows links; d.Info does not. Hugging Face lays its
				// cache out as snapshots/ links into blobs/, so d.Info reports
				// every weight file on Windows as zero bytes.
				if info, err := os.Stat(path); err == nil {
					pickles[path] = info.Size()
				} else {
					pickles[path] = -1
				}
			case safeExts[ext]:
				safeCount++
			}
			return nil
		})
	}

	reportPickles(r, chosen, managed, pickleCount, safeCount)
	return inv
}

func reportPickles(r *model.Report, chosen, managed map[string]int64, pickleCount, safeCount int) {
	if pickleCount == 0 {
		if safeCount > 0 {
			r.Add(model.Finding{
				ID: "MDL-000", Title: fmt.Sprintf("All %d local model files use safe container formats", safeCount),
				Severity: model.Info,
				Detail:   "Only .safetensors, .gguf and .onnx weights were found. These formats cannot execute code when loaded.",
			})
		}
		return
	}

	const format = "Weights ending in .ckpt, .pt, .pth, .bin or .pkl are Python pickles: loading one executes whatever it contains. "

	if len(chosen) > 0 {
		r.Add(model.Finding{
			ID:       "MDL-001",
			Title:    fmt.Sprintf("%d model file(s) you added yourself run code when loaded", len(chosen)),
			Severity: model.Medium,
			Detail: format + "These sit in a model folder you manage, so they arrived because someone chose to put them there -- " +
				"which is exactly the path a malicious checkpoint from a forum or a model-sharing site takes onto a machine.",
			Evidence: pickleEvidence(chosen),
			Fix: "Prefer the .safetensors build of the same model; most publishers now ship one. If you must load a pickle, " +
				"only do so from a publisher you trust, and load it in a container or a throwaway user account.",
			Ref: "https://huggingface.co/docs/hub/security-pickle",
		})
	}

	if len(managed) > 0 {
		r.Add(model.Finding{
			ID:       "MDL-002",
			Title:    fmt.Sprintf("%d cached model file(s) use a format that runs code when loaded", len(managed)),
			Severity: model.Low,
			Detail: format + "These are in caches that PyTorch, Hugging Face or Ollama filled themselves, so a library asked for " +
				"each one by name rather than a person dropping it in. That is a much narrower risk than a checkpoint you " +
				"downloaded by hand, but the format still executes on load, so it is worth knowing they are there.",
			Evidence: pickleEvidence(managed),
			Fix:      "Nothing needs to be done today. When you next pick a model, prefer a publisher that ships .safetensors.",
			Ref:      "https://huggingface.co/docs/hub/security-pickle",
		})
	}

	if safeCount > 0 {
		r.Add(model.Finding{
			ID:       "MDL-000",
			Title:    fmt.Sprintf("%d model file(s) use safe container formats", safeCount),
			Severity: model.Info,
			Detail:   ".safetensors, .gguf and .onnx weights cannot execute code when loaded.",
		})
	}
}

// pickleEvidence lists every file, largest first, with no cut-off.
func pickleEvidence(m map[string]int64) []string {
	type e struct {
		path string
		size int64
	}
	list := make([]e, 0, len(m))
	for p, s := range m {
		list = append(list, e{p, s})
	}
	// Largest first, then by path. The path tiebreak is what makes this
	// deterministic: the input is a map, so Go hands it over in a different
	// order every run, and two files of the same size swapped places between
	// two scans of an unchanged machine. A tool that asks people to compare
	// reports over time must not produce a diff when nothing changed.
	sort.Slice(list, func(i, j int) bool {
		if list[i].size != list[j].size {
			return list[i].size > list[j].size
		}
		return list[i].path < list[j].path
	})

	out := make([]string, 0, len(list))
	for _, x := range list {
		size := humanSize(x.size)
		if x.size < 0 {
			size = "size unknown"
		}
		out = append(out, fmt.Sprintf("%s  (%s)", x.path, size))
	}
	return out
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
