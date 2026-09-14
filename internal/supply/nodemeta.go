package supply

import (
	"os"
	"path/filepath"
	"strings"
)

// nodeMetadata reads the version and origin a ComfyUI custom node declares
// about itself.
//
// Reading .git/config covers nodes installed with git, which is what
// ComfyUI-Manager does. It covers nothing installed from the Comfy Registry:
// the desktop app downloads a published archive with no .git directory at all,
// so a machine's whole node list showed an empty version and source. What those
// nodes do carry is a pyproject.toml with the registry's own metadata.
//
// This is a deliberately small reader rather than a TOML parser. The fields
// wanted are four scalars in two known tables, and a dependency-free build is
// a product claim here.
func nodeMetadata(dir string) map[string]string {
	if d := gitDetail(dir); d != nil {
		return d
	}
	return pyprojectDetail(dir)
}

// pyprojectDetail pulls name, version, repository and publisher out of a
// ComfyUI Registry node's pyproject.toml.
func pyprojectDetail(dir string) map[string]string {
	b, err := os.ReadFile(filepath.Join(dir, "pyproject.toml"))
	if err != nil || len(b) > 1<<20 {
		return nil
	}

	out := map[string]string{}
	section := ""
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
			continue
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}

		key, value, ok := scalar(line)
		if !ok {
			continue
		}
		switch {
		case section == "project" && key == "version":
			out["version"] = value
		case section == "project.urls" && strings.EqualFold(key, "repository"):
			out["origin"] = value
		case section == "tool.comfy" && strings.EqualFold(key, "publisherid"):
			out["publisher"] = value
		case section == "tool.comfy" && strings.EqualFold(key, "displayname"):
			out["display_name"] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	out["metadata"] = "pyproject.toml"
	return out
}

// scalar reads a `key = "value"` line. Anything else -- a table, an array, a
// multi-line string -- is skipped rather than guessed at, because a wrong
// version in this report is worse than an absent one.
func scalar(line string) (key, value string, ok bool) {
	eq := strings.Index(line, "=")
	if eq < 1 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:eq])
	rest := strings.TrimSpace(line[eq+1:])
	if len(rest) < 2 {
		return "", "", false
	}
	quote := rest[0]
	if quote != '"' && quote != '\'' {
		return "", "", false
	}
	end := strings.IndexByte(rest[1:], quote)
	if end < 0 {
		return "", "", false
	}
	value = rest[1 : 1+end]
	if value == "" || strings.ContainsAny(key, " \t") {
		return "", "", false
	}
	return key, value, true
}
