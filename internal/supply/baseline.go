package supply

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrNoBaseline means drift detection has nothing to compare against yet.
var ErrNoBaseline = errors.New("no baseline recorded yet")

// DefaultBaselinePath is where the accepted state is remembered.
func DefaultBaselinePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "aiexpose-baseline.json"
	}
	return filepath.Join(home, ".aiexpose", "baseline.json")
}

// LoadBaseline reads a previously accepted inventory.
func LoadBaseline(path string) (Inventory, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Inventory{}, ErrNoBaseline
		}
		return Inventory{}, err
	}
	var inv Inventory
	if err := json.Unmarshal(b, &inv); err != nil {
		return Inventory{}, fmt.Errorf("baseline at %s is not readable: %w", path, err)
	}
	return inv, nil
}

// SaveBaseline records the inventory as the accepted state. The file is
// written 0600: it lists what is installed, which is not for other users.
func SaveBaseline(path string, inv Inventory) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
