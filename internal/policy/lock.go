package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/MC-kakadu/AIexpose/internal/supply"
)

// LockFileName is the committed record of which components a repository has
// reviewed and accepted.
const LockFileName = "aiexpose.lock.json"

// ErrNoLock means the repository has not recorded an accepted set yet.
var ErrNoLock = errors.New("no lockfile in this repository")

// LockedComponent is one accepted component, in a form that is identical on
// every machine so the file diffs cleanly in review.
type LockedComponent struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Path    string `json:"path"`
	Digest  string `json:"digest"`
	Package string `json:"package,omitempty"`
	Version string `json:"version,omitempty"`
	Spec    string `json:"spec,omitempty"`
}

// Lock is the whole accepted set.
type Lock struct {
	Version    int               `json:"version"`
	Generated  time.Time         `json:"generated"`
	Components []LockedComponent `json:"components"`
}

// NewLock builds a lockfile from an inventory.
func NewLock(inv supply.Inventory) Lock {
	l := Lock{Version: 1, Generated: time.Now().UTC()}
	for _, a := range inv.Artifacts {
		l.Components = append(l.Components, LockedComponent{
			ID: a.ID, Kind: a.Kind, Name: a.Name, Path: a.Path,
			Digest:  a.Digest,
			Package: a.Detail["package"], Version: a.Detail["package_version"],
			Spec: a.Detail["spec"],
		})
	}
	sort.Slice(l.Components, func(i, j int) bool { return l.Components[i].ID < l.Components[j].ID })
	return l
}

// LoadLock reads the committed lockfile.
func LoadLock(path string) (Lock, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Lock{}, ErrNoLock
		}
		return Lock{}, err
	}
	var l Lock
	if err := json.Unmarshal(b, &l); err != nil {
		return Lock{}, fmt.Errorf("%s is not readable: %w", path, err)
	}
	return l, nil
}

// SaveLock writes the lockfile for committing to the repository.
func SaveLock(path string, l Lock) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// Index maps component IDs to their locked state.
func (l Lock) Index() map[string]LockedComponent {
	m := make(map[string]LockedComponent, len(l.Components))
	for _, c := range l.Components {
		m[c.ID] = c
	}
	return m
}
