//go:build windows || darwin

package browse

// hasDisplay is always true here: both platforms hand the file to the shell,
// which knows what to do with it whether or not anyone is looking.
func hasDisplay() bool { return true }
