package supply

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Ollama models are inventoried by reading the manifests and blobs on disk
// rather than by asking the running server.
//
// Reading files works whether or not Ollama is running, and it adds no
// behaviour this tool does not already perform: the model-format check already
// walks this exact directory. Talking to the API would mean a scan behaving
// differently depending on what happens to be running, for no gain.
const (
	// officialRegistry is where `ollama pull llama3` gets its models. Anything
	// else was pulled from somewhere the user chose.
	officialRegistry = "registry.ollama.ai"

	// smallLayerLimit bounds the layers read in full. The system prompt and
	// template are a few kilobytes; the weights are gigabytes, and hashing
	// those on every scan would turn a three-second run into minutes.
	smallLayerLimit = 1 << 20
)

// layerKinds maps Ollama's media types to a short name.
var layerKinds = map[string]string{
	"application/vnd.ollama.image.model":    "weights",
	"application/vnd.ollama.image.system":   "system-prompt",
	"application/vnd.ollama.image.template": "template",
	"application/vnd.ollama.image.params":   "params",
	"application/vnd.ollama.image.adapter":  "adapter",
	"application/vnd.ollama.image.license":  "license",
	"application/vnd.ollama.image.messages": "messages",
	"application/vnd.ollama.image.prompt":   "prompt",
}

// readInFull are the layers whose text steers the model's behaviour. They are
// small, and they are where a tampered model does its damage: a system prompt
// is an instruction the model follows on every request.
var readInFull = map[string]bool{
	"system-prompt": true, "template": true, "params": true,
	"messages": true, "prompt": true,
}

type ollamaLayer struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type ollamaManifest struct {
	SchemaVersion int           `json:"schemaVersion"`
	Layers        []ollamaLayer `json:"layers"`
}

// ollamaRoots returns every models directory that exists.
func ollamaRoots(home string) []string {
	var out []string
	if env := os.Getenv("OLLAMA_MODELS"); env != "" {
		out = append(out, env)
	}
	out = append(out, filepath.Join(home, ".ollama", "models"))
	var exist []string
	for _, d := range dedupe(out) {
		if st, err := os.Stat(filepath.Join(d, "manifests")); err == nil && st.IsDir() {
			exist = append(exist, d)
		}
	}
	return exist
}

// ollamaArtifacts inventories the models installed under one models directory.
func ollamaArtifacts(root string, budget *walkBudget) []Artifact {
	manifests := filepath.Join(root, "manifests")
	blobs := filepath.Join(root, "blobs")

	var out []Artifact
	_ = filepath.WalkDir(manifests, func(path string, d os.DirEntry, err error) error {
		if err != nil || budget.spent() {
			return skipOn(err, budget)
		}
		if d.IsDir() {
			return nil
		}
		budget.file()
		if a, ok := readOllamaModel(manifests, blobs, path); ok {
			out = append(out, a)
		}
		return nil
	})
	return out
}

func readOllamaModel(manifestRoot, blobRoot, path string) (Artifact, bool) {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > smallLayerLimit {
		return Artifact{}, false
	}
	var m ollamaManifest
	if err := json.Unmarshal(raw, &m); err != nil || len(m.Layers) == 0 {
		return Artifact{}, false
	}

	// manifests/<registry>/<namespace>/<model>/<tag>
	rel, err := filepath.Rel(manifestRoot, path)
	if err != nil {
		return Artifact{}, false
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) < 4 {
		return Artifact{}, false
	}
	registry, namespace, name, tag := parts[0], parts[1], strings.Join(parts[2:len(parts)-1], "/"), parts[len(parts)-1]

	label := name + ":" + tag
	if namespace != "library" {
		label = namespace + "/" + label
	}

	detail := map[string]string{"registry": registry}
	if registry != officialRegistry {
		detail["unofficial_registry"] = registry
	}

	h := sha256.New()
	h.Write(raw)

	var (
		kinds      []string
		tampered   []string
		totalSize  int64
		indicators []Indicator
	)
	for _, l := range m.Layers {
		kind := layerKinds[l.MediaType]
		if kind == "" {
			kind = "other"
		}
		kinds = append(kinds, kind)
		totalSize += l.Size

		if !readInFull[kind] || l.Size > smallLayerLimit {
			continue
		}
		body, ok, intact := readBlob(blobRoot, l.Digest)
		if !ok {
			continue
		}
		if !intact {
			// Ollama names every blob after the hash of its own contents, so a
			// blob that does not hash to its own filename was changed after it
			// was downloaded. Nothing legitimate does that.
			tampered = append(tampered, kind+" ("+shortDigest(l.Digest)+")")
		}
		// The steering text is part of the model's identity: a changed system
		// prompt must show up as drift even though the weights are untouched.
		h.Write([]byte(kind))
		h.Write(body)

		if kind == "system-prompt" || kind == "template" || kind == "prompt" {
			indicators = append(indicators, scanText(path+" ("+kind+")", string(body))...)
			if kind == "system-prompt" && len(strings.TrimSpace(string(body))) > 0 {
				detail["system_prompt"] = "present"
			}
		}
	}
	sort.Strings(kinds)
	detail["layers"] = strings.Join(dedupe(kinds), ",")
	detail["size"] = humanBytes(totalSize)
	if len(tampered) > 0 {
		detail["tampered"] = strings.Join(tampered, "; ")
	}
	for _, k := range kinds {
		if k == "adapter" {
			detail["adapter"] = "present"
		}
	}

	return Artifact{
		Kind: "ollama-model", ID: "ollama-model:" + registry + "/" + namespace + "/" + name + ":" + tag,
		Name: label, Path: path,
		Digest:    hex.EncodeToString(h.Sum(nil)),
		FileCount: len(m.Layers), Detail: detail, Indicators: indicators,
	}, true
}

// readBlob returns a blob's contents and whether it still hashes to its name.
func readBlob(blobRoot, digest string) (body []byte, ok bool, intact bool) {
	want := strings.TrimPrefix(digest, "sha256:")
	path := filepath.Join(blobRoot, "sha256-"+want)
	f, err := os.Open(path)
	if err != nil {
		return nil, false, false
	}
	defer f.Close()

	b, err := io.ReadAll(io.LimitReader(f, smallLayerLimit))
	if err != nil {
		return nil, false, false
	}
	sum := sha256.Sum256(b)
	return b, true, strings.EqualFold(hex.EncodeToString(sum[:]), want)
}

func shortDigest(d string) string {
	d = strings.TrimPrefix(d, "sha256:")
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return itoa64(n) + " B"
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	whole := n / div
	frac := (n % div) * 10 / div
	return itoa64(whole) + "." + itoa64(frac) + string("KMGTPE"[exp]) + "iB"
}

func itoa64(i int64) string {
	if i == 0 {
		return "0"
	}
	var b [24]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
