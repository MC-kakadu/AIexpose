package supply

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Artifact is one installed thing that can execute code inside your AI stack.
type Artifact struct {
	Kind       string            `json:"kind"` // comfy-node | mcp-server | agent-skill
	ID         string            `json:"id"`   // stable across runs
	Name       string            `json:"name"`
	Path       string            `json:"path"`
	Digest     string            `json:"digest"` // sha256 over executable content
	FileCount  int               `json:"file_count"`
	Detail     map[string]string `json:"detail,omitempty"`
	Indicators []Indicator       `json:"indicators,omitempty"`

	// FileDigests is kept in memory for threat-feed matching only. It is left
	// out of the baseline on purpose: a hash per file would bloat that file for
	// no benefit, since drift is already detected by Digest.
	FileDigests []string `json:"-"`

	// Hashes carries a whole-file MD5 per file, for matching against a local
	// malware-hash index. It is collected only when an index exists, because
	// filling it means opening binaries the rest of the scan has no reason to
	// read. Like FileDigests it never reaches the baseline.
	Hashes []FileHash `json:"-"`
}

// FileHash is one file's MD5, kept with its path so a match can name the file
// rather than only the component it sits in, and with its size so a caller can
// refuse to match a file too small for a hash to mean anything.
type FileHash struct {
	Rel  string
	Sum  [16]byte
	Size int64
}

// Inventory is a point-in-time record of every artifact.
type Inventory struct {
	Taken     time.Time  `json:"taken"`
	OS        string     `json:"os"`
	Artifacts []Artifact `json:"artifacts"`
	Roots     []string   `json:"roots,omitempty"`
	Skipped   []string   `json:"skipped,omitempty"`
}

// walkBudget caps how much work a scan may do, so a scan never hangs on a
// pathological directory tree.
type walkBudget struct {
	deadline time.Time
	files    int
	maxFiles int

	// hashedBytes caps how much file content whole-file hashing may read.
	// Digest hashing is bounded by its own 8 MB per-file limit; MD5 hashing is
	// not, so without this one directory full of large binaries could turn a
	// three-second scan into a three-minute one.
	hashedBytes int64
	maxBytes    int64
}

func newBudget(d time.Duration, maxFiles int) *walkBudget {
	return &walkBudget{deadline: time.Now().Add(d), maxFiles: maxFiles, maxBytes: maxHashBytes}
}
func (b *walkBudget) file()       { b.files++ }
func (b *walkBudget) spent() bool { return b.files > b.maxFiles || time.Now().After(b.deadline) }

// bytesLeft reports whether there is still room in the read budget, and books
// the read if there is.
func (b *walkBudget) takeBytes(n int64) bool {
	if b.hashedBytes+n > b.maxBytes {
		return false
	}
	b.hashedBytes += n
	return true
}

// hashedExts contribute to an artifact's digest. Weights and caches are
// excluded so that a model download does not look like a code change.
var hashedExts = map[string]bool{
	".py": true, ".js": true, ".mjs": true, ".cjs": true, ".ts": true,
	".sh": true, ".bash": true, ".ps1": true, ".bat": true, ".cmd": true,
	".rb": true, ".pl": true, ".json": true, ".toml": true, ".yaml": true,
	".yml": true, ".cfg": true, ".txt": true, ".md": true,
}

// binaryExts are hashed for malware matching but deliberately kept out of the
// artifact digest. A compiled extension or a bundled archive is exactly the
// kind of file a public malware corpus is made of, and exactly the kind whose
// arrival should not, on its own, make a node look like it changed its code.
var binaryExts = map[string]bool{
	".exe": true, ".dll": true, ".sys": true, ".scr": true, ".com": true,
	".msi": true, ".cab": true, ".pyd": true, ".node": true, ".so": true,
	".dylib": true, ".jar": true, ".class": true, ".wasm": true,
	".zip": true, ".whl": true, ".7z": true, ".rar": true,
	".vbs": true, ".vbe": true, ".jse": true, ".wsf": true, ".hta": true,
	".lnk": true, ".reg": true,
}

const (
	// digestLimit is how much of a file feeds the artifact digest. It must not
	// change: every baseline already recorded on a user's machine was built
	// with it, and widening it would report every component as modified.
	digestLimit = 8 << 20

	// md5FileLimit skips whole-file hashing for anything larger. Model weights
	// are gigabytes and will never appear in a malware corpus; paying to read
	// them would buy nothing.
	md5FileLimit = 64 << 20

	// maxHashBytes bounds the total content one scan may read for hashing.
	maxHashBytes = 1 << 30
)

// Options tunes what an inventory costs to take.
type Options struct {
	// MD5 turns on whole-file MD5 collection. It is off unless a malware hash
	// index exists to match against, so the ordinary scan never opens a binary
	// it has no use for.
	MD5 bool
}

// Take builds the current inventory with default options.
func Take() Inventory { return TakeWith(Options{}) }

// TakeWith builds the current inventory.
func TakeWith(opt Options) Inventory {
	inv := Inventory{Taken: time.Now().UTC(), OS: runtime.GOOS}
	home, err := os.UserHomeDir()
	if err != nil {
		inv.Skipped = append(inv.Skipped, "home directory could not be resolved")
		return inv
	}

	budget := newBudget(20*time.Second, 120000)

	for _, root := range comfyNodeRoots(home) {
		inv.Roots = append(inv.Roots, root)
		inv.Artifacts = append(inv.Artifacts, dirArtifacts("comfy-node", root, budget, opt)...)
	}
	for _, root := range skillRoots(home) {
		inv.Roots = append(inv.Roots, root)
		inv.Artifacts = append(inv.Artifacts, dirArtifacts("agent-skill", root, budget, opt)...)
	}
	for _, root := range ollamaRoots(home) {
		inv.Roots = append(inv.Roots, root)
		inv.Artifacts = append(inv.Artifacts, ollamaArtifacts(root, budget)...)
	}
	for _, cfg := range mcpConfigPaths(home) {
		if arts := mcpArtifacts(cfg); len(arts) > 0 {
			inv.Roots = append(inv.Roots, cfg)
			inv.Artifacts = append(inv.Artifacts, arts...)
		}
	}

	if budget.spent() {
		inv.Skipped = append(inv.Skipped, "the inventory hit its time or file budget and may be incomplete")
	}
	if opt.MD5 && budget.hashedBytes >= budget.maxBytes {
		inv.Skipped = append(inv.Skipped,
			"file hashing hit its 1 GB read budget, so some files were not checked against the malware hash index")
	}
	sort.Slice(inv.Artifacts, func(i, j int) bool { return inv.Artifacts[i].ID < inv.Artifacts[j].ID })
	return inv
}

// comfyNodeRoots returns every custom_nodes directory that exists.
//
// The list is long because ComfyUI has no single install location, and a
// component the scan never looks at is a component it silently vouches for. The
// case that forced this open was the ComfyUI Desktop app: it puts nothing under
// the home directory at all, keeping each install under
// %LOCALAPPDATA%\Comfy-Desktop\ComfyUI-Installs\<name>\ComfyUI, so a machine
// with ComfyUI installed reported zero nodes.
func comfyNodeRoots(home string) []string {
	bases := []string{
		filepath.Join(home, "ComfyUI"),
		filepath.Join(home, "comfyui"),
		filepath.Join(home, "ComfyUI_windows_portable", "ComfyUI"),
		filepath.Join(home, "Documents", "ComfyUI"),
		filepath.Join(home, "Desktop", "ComfyUI"),
		filepath.Join(home, "Downloads", "ComfyUI"),
		filepath.Join(home, "Documents", "ComfyUI_windows_portable", "ComfyUI"),
		filepath.Join(home, "Desktop", "ComfyUI_windows_portable", "ComfyUI"),
		filepath.Join(home, "Downloads", "ComfyUI_windows_portable", "ComfyUI"),
	}
	bases = append(bases, desktopAppInstalls(home)...)

	// A portable build unzipped to a drive root is the most common Windows
	// layout after the desktop app, and none of it lives under the home
	// directory.
	for _, drive := range fixedDrives() {
		bases = append(bases,
			filepath.Join(drive, "ComfyUI"),
			filepath.Join(drive, "ComfyUI_windows_portable", "ComfyUI"),
		)
	}
	if env := os.Getenv("COMFYUI_PATH"); env != "" {
		bases = append(bases, env)
	}

	var out []string
	for _, b := range bases {
		d := filepath.Join(b, "custom_nodes")
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			out = append(out, d)
		}
	}
	return dedupe(out)
}

// comfyDesktopRoots are the directories the ComfyUI Desktop app keeps its
// installs under. Each one holds a folder per install, and the ComfyUI tree is
// one level inside that.
func comfyDesktopRoots(home string) []string {
	var roots []string
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		roots = append(roots, filepath.Join(local, "Comfy-Desktop", "ComfyUI-Installs"))
	}
	// Older desktop versions installed to the home directory instead.
	roots = append(roots, filepath.Join(home, "ComfyUI-Installs"))
	return roots
}

// desktopAppInstalls expands each desktop install directory into the ComfyUI
// tree inside it. Install names are chosen by the user, so they have to be
// read rather than guessed.
func desktopAppInstalls(home string) []string {
	var out []string
	for _, root := range comfyDesktopRoots(home) {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				out = append(out, filepath.Join(root, e.Name(), "ComfyUI"))
			}
		}
	}
	return out
}

// skillRoots returns directories holding agent skills, which are instructions
// an agent will follow and scripts it may run.
func skillRoots(home string) []string {
	cands := []string{
		filepath.Join(home, ".claude", "skills"),
		filepath.Join(home, ".config", "claude", "skills"),
	}
	if appData := os.Getenv("APPDATA"); appData != "" {
		cands = append(cands, filepath.Join(appData, "Claude", "skills"))
	}
	var out []string
	for _, d := range cands {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			out = append(out, d)
		}
	}
	return dedupe(out)
}

// dirArtifacts treats each immediate subdirectory of root as one artifact.
func dirArtifacts(kind, root string, budget *walkBudget, opt Options) []Artifact {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []Artifact
	for _, e := range entries {
		// skipDir already lists the directories a tool creates for itself.
		// It was only being consulted inside the tree walk, so __pycache__
		// next to the real nodes was inventoried as a component of its own --
		// one with no code in it, whose digest was the hash of nothing.
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") || skipDir(e.Name()) || budget.spent() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		tree := hashTree(dir, budget, opt)
		// A directory holding no code or config at all is not a component.
		// Listing one invites the reader to review something that does not
		// exist, and it cannot drift, because there is nothing in it to change.
		if tree.count == 0 && len(tree.md5s) == 0 {
			continue
		}
		a := Artifact{
			Kind: kind, ID: kind + ":" + e.Name(), Name: e.Name(),
			Path: dir, Digest: tree.digest, FileCount: tree.count,
			Detail: nodeMetadata(dir), FileDigests: tree.fileDigests,
			Hashes: tree.md5s,
		}
		a.Indicators = scanTree(dir, budget)
		out = append(out, a)
	}
	return out
}

// treeHashes is what one walk of an artifact directory produces.
type treeHashes struct {
	digest      string
	count       int
	fileDigests []string
	md5s        []FileHash
}

// hashTree produces a digest over an artifact's executable and config files.
// Path names are folded in, so adding or renaming a file changes the digest.
//
// When opt.MD5 is set the same walk also collects a whole-file MD5, over a
// wider set of extensions: the digest deliberately ignores compiled and
// archived files, but those are precisely what a malware corpus indexes.
func hashTree(dir string, budget *walkBudget, opt Options) treeHashes {
	type entry struct{ rel, sum string }
	var entries []entry
	var md5s []FileHash

	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || budget.spent() {
			return skipOn(err, budget)
		}
		if d.IsDir() {
			if skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		inDigest := hashedExts[ext]
		wantMD5 := opt.MD5 && (inDigest || binaryExts[ext])
		if !inDigest && !wantMD5 {
			return nil
		}
		budget.file()

		var size int64 = -1
		if wantMD5 {
			// Follow symlinks and read the real size: a link reports zero
			// bytes and would otherwise slip past the budget unmeasured.
			st, serr := os.Stat(path)
			switch {
			case serr != nil:
				wantMD5 = false
			case st.Size() > md5FileLimit:
				wantMD5 = false
			case !budget.takeBytes(st.Size()):
				wantMD5 = false
			default:
				size = st.Size()
			}
		}
		if !inDigest && !wantMD5 {
			return nil
		}

		sum, md5sum, gotMD5, err := fileHashes(path, inDigest, wantMD5)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		rel = filepath.ToSlash(rel)
		if inDigest {
			entries = append(entries, entry{rel, sum})
		}
		if gotMD5 {
			md5s = append(md5s, FileHash{Rel: rel, Sum: md5sum, Size: size})
		}
		return nil
	})

	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	sort.Slice(md5s, func(i, j int) bool { return md5s[i].Rel < md5s[j].Rel })

	h := sha256.New()
	sums := make([]string, 0, len(entries))
	for _, e := range entries {
		_, _ = io.WriteString(h, e.rel+"\x00"+e.sum+"\n")
		sums = append(sums, e.sum)
	}
	return treeHashes{
		digest: hex.EncodeToString(h.Sum(nil)), count: len(entries),
		fileDigests: sums, md5s: md5s,
	}
}

// fileHashes reads a file once and produces up to two hashes from it.
//
// The two halves have different rules on purpose. The SHA-256 that feeds the
// artifact digest covers at most the first 8 MB, and has to keep doing so:
// every baseline already sitting on a user's machine was computed that way.
// The MD5 covers the whole file, because a corpus records whole-file hashes and
// a partial one would match nothing.
func fileHashes(path string, wantSHA, wantMD5 bool) (sha string, sum [16]byte, gotMD5 bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", sum, false, err
	}
	defer f.Close()

	sh := sha256.New()
	m := md5.New()

	var dst io.Writer
	var src io.Reader = f
	switch {
	case wantSHA && wantMD5:
		dst = io.MultiWriter(&capped{w: sh, left: digestLimit}, m)
	case wantMD5:
		dst = m
	default:
		dst, src = sh, io.LimitReader(f, digestLimit)
	}
	if _, err := io.Copy(dst, src); err != nil {
		return "", sum, false, err
	}
	if wantSHA {
		sha = hex.EncodeToString(sh.Sum(nil))
	}
	if wantMD5 {
		copy(sum[:], m.Sum(nil))
		gotMD5 = true
	}
	return sha, sum, gotMD5, nil
}

// capped forwards the first left bytes and silently drops the rest, so one
// pass over a file can feed a bounded hash and an unbounded one at once.
type capped struct {
	w    io.Writer
	left int64
}

func (c *capped) Write(p []byte) (int, error) {
	n := int64(len(p))
	if c.left <= 0 {
		return int(n), nil
	}
	if n > c.left {
		p = p[:c.left]
	}
	written, err := c.w.Write(p)
	c.left -= int64(written)
	return int(n), err
}

// gitDetail records where a node came from, when that is knowable.
func gitDetail(dir string) map[string]string {
	b, err := os.ReadFile(filepath.Join(dir, ".git", "config"))
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "url = ") {
			return map[string]string{"origin": strings.TrimSpace(strings.TrimPrefix(line, "url = "))}
		}
	}
	return nil
}

// --- MCP server configs -------------------------------------------------

type mcpServer struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	URL     string            `json:"url"`
	Type    string            `json:"type"`
}

type mcpFile struct {
	MCPServers map[string]mcpServer `json:"mcpServers"`
	Servers    map[string]mcpServer `json:"servers"`
}

func mcpConfigPaths(home string) []string {
	var p []string
	switch runtime.GOOS {
	case "windows":
		if appData := os.Getenv("APPDATA"); appData != "" {
			p = append(p, filepath.Join(appData, "Claude", "claude_desktop_config.json"))
		}
	case "darwin":
		p = append(p, filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"))
	default:
		p = append(p, filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"))
	}
	p = append(p,
		filepath.Join(home, ".cursor", "mcp.json"),
		filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"),
		filepath.Join(home, ".claude.json"),
		filepath.Join(home, ".claude", "settings.json"),
		filepath.Join(home, ".vscode", "mcp.json"),
		filepath.Join(home, ".continue", "config.json"),
	)
	return dedupe(p)
}

func mcpArtifacts(path string) []Artifact {
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 4<<20 {
		return nil
	}
	var f mcpFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil
	}
	servers := f.MCPServers
	if len(servers) == 0 {
		servers = f.Servers
	}

	var out []Artifact
	for name, s := range servers {
		detail := map[string]string{"config": path}
		spec := strings.TrimSpace(s.Command + " " + strings.Join(s.Args, " "))
		if s.URL != "" {
			spec = s.URL
			detail["transport"] = "remote"
		} else {
			detail["transport"] = "stdio"
		}
		detail["spec"] = spec
		if pkg, ok := unpinnedPackage(s.Command, s.Args); ok {
			detail["unpinned"] = pkg
		}
		if name, ver, ok := packageSpec(s.Command, s.Args); ok {
			detail["package"] = name
			if ver != "" {
				detail["package_version"] = ver
			}
		}
		// Environment variable NAMES only. Values are credentials.
		if len(s.Env) > 0 {
			keys := make([]string, 0, len(s.Env))
			for k := range s.Env {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			detail["env_keys"] = strings.Join(keys, ",")
		}
		sum := sha256.Sum256([]byte(spec + "\x00" + detail["env_keys"]))
		out = append(out, Artifact{
			Kind: "mcp-server", ID: "mcp-server:" + name + "@" + filepath.Base(path),
			Name: name, Path: path,
			Digest: hex.EncodeToString(sum[:]), Detail: detail,
		})
	}
	return out
}

// runners fetch and execute a package at launch time, so an unpinned spec
// means today's code is not necessarily what you reviewed yesterday.
var runners = map[string]bool{
	"npx": true, "npx.cmd": true, "bunx": true, "pnpm": true,
	"uvx": true, "pipx": true, "uv": true,
}

// baseName returns the final path element regardless of which separator the
// config used. A config file can carry Windows-style paths while being parsed
// anywhere, so filepath.Base alone is not enough.
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// packageSpec splits the registry package a server launches into its name and
// version. Scoped npm names begin with @, so the separator is the last @ rather
// than the first; Python runners pin with == instead.
func packageSpec(command string, args []string) (name, version string, ok bool) {
	if !runners[strings.ToLower(baseName(command))] {
		return "", "", false
	}
	for _, a := range args {
		if strings.HasPrefix(a, "-") || a == "dlx" || a == "run" || a == "tool" {
			continue
		}
		if i := strings.Index(a, "=="); i > 0 {
			return a[:i], a[i+2:], true
		}
		body := a
		prefix := ""
		if strings.HasPrefix(body, "@") {
			prefix, body = "@", body[1:]
		}
		if i := strings.LastIndex(body, "@"); i > 0 {
			return prefix + body[:i], body[i+1:], true
		}
		return a, "", true
	}
	return "", "", false
}

// unpinnedPackage reports the package spec when a server launches through a
// runner without a pinned version.
func unpinnedPackage(command string, args []string) (string, bool) {
	base := strings.ToLower(baseName(command))
	if !runners[base] {
		return "", false
	}
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue // -y, --yes, --from and friends
		}
		if a == "dlx" || a == "run" || a == "tool" {
			continue
		}
		if strings.Contains(a, "@latest") || strings.HasSuffix(a, "@") {
			return a, true
		}
		// Scoped npm names begin with @, so a version pin is a later @.
		name := a
		if strings.HasPrefix(name, "@") {
			name = name[1:]
		}
		if strings.Contains(name, "@") || strings.Contains(a, "==") {
			return "", false // pinned
		}
		return a, true
	}
	return "", false
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
