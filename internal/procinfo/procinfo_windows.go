//go:build windows

package procinfo

// fullCommand returns nothing on Windows, deliberately.
//
// Reading another process's command line means either spawning PowerShell to
// call Get-CimInstance -- a behavioural detection trigger for an unsigned
// binary -- or reading that process's memory through the PEB, which is worse.
// Neither is worth it: the launch-flag check still works from environment
// variables, and the exposure checks do not depend on this at all.
func fullCommand(int) string { return "" }
