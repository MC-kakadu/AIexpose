//go:build !linux && !darwin && !windows

package procinfo

func fullCommand(int) string { return "" }
