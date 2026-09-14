//go:build !windows

package main

// On Unix a terminal is not destroyed when the program exits, so there is
// never anything to hold open.
func consoleIsOurs() bool { return false }
