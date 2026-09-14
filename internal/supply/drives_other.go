//go:build !windows

package supply

// fixedDrives is a Windows notion. Everywhere else the filesystem has one root
// and the home-relative candidates already cover it.
func fixedDrives() []string { return nil }
