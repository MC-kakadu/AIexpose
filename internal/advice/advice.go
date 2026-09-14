// Package advice turns a finding into the exact step that resolves it on this
// operating system.
//
// It only ever produces text. Earlier versions of this tool applied the changes
// themselves, and that was a mistake for a reason we measured rather than
// guessed: writing to HKCU\Environment, editing launch scripts and deleting
// router port mappings are, to a behaviour engine watching an unsigned binary,
// indistinguishable from malware establishing persistence. Kaspersky blocked an
// earlier build for exactly that shape of activity.
//
// So aiexpose reads and reports. The machine is changed by the person who owns
// it, with a command they can see before they run it.
package advice

import (
	"fmt"
	"runtime"
	"strings"
)

// OllamaBind returns the command that puts Ollama's API back on loopback.
func OllamaBind() string {
	switch runtime.GOOS {
	case "windows":
		return `setx OLLAMA_HOST "127.0.0.1:11434"`
	case "darwin":
		return `launchctl setenv OLLAMA_HOST "127.0.0.1:11434"`
	default:
		return `systemctl --user set-environment OLLAMA_HOST=127.0.0.1:11434`
	}
}

// OllamaBindNote explains what has to happen for the change to take effect.
func OllamaBindNote() string {
	switch runtime.GOOS {
	case "windows":
		return "Then quit Ollama from the tray and start it again; a running process keeps the environment it was started with."
	case "darwin":
		return "Then quit the Ollama app and reopen it. launchctl setenv does not survive a reboot, so add it to a LaunchAgent if you want it to stick."
	default:
		return "Then restart the service: systemctl --user restart ollama"
	}
}

// OllamaOrigins narrows which browser origins may drive Ollama.
func OllamaOrigins(origin string) string {
	if origin == "" {
		origin = "http://localhost:3000"
	}
	switch runtime.GOOS {
	case "windows":
		return fmt.Sprintf(`setx OLLAMA_ORIGINS "%s"`, origin)
	case "darwin":
		return fmt.Sprintf(`launchctl setenv OLLAMA_ORIGINS "%s"`, origin)
	default:
		return fmt.Sprintf(`systemctl --user set-environment OLLAMA_ORIGINS=%s`, origin)
	}
}

// UnsetEnv removes an environment variable that widens exposure.
func UnsetEnv(name string) string {
	switch runtime.GOOS {
	case "windows":
		return fmt.Sprintf(`reg delete HKCU\Environment /F /V %s`, name)
	case "darwin":
		return fmt.Sprintf(`launchctl unsetenv %s`, name)
	default:
		return fmt.Sprintf(`unset %s   # and remove it from your shell profile`, name)
	}
}

// RestrictFile makes a file readable only by its owner.
func RestrictFile(path string) string {
	if runtime.GOOS == "windows" {
		return fmt.Sprintf(`icacls "%s" /inheritance:r /grant:r "%%USERNAME%%:F"`, path)
	}
	return fmt.Sprintf("chmod 600 %s", shellQuote(path))
}

// EnableFirewall is deliberately only ever printed.
//
// Turning on a default-deny firewall is the one suggestion that can lock a
// person out of the machine they are reading this on, so it names the risk and
// puts the ssh rule first.
func EnableFirewall() string {
	switch runtime.GOOS {
	case "windows":
		return "Set-NetFirewallProfile -All -Enabled True    # elevated PowerShell"
	case "darwin":
		return "System Settings > Network > Firewall: turn it on, and enable stealth mode."
	default:
		return "sudo ufw allow ssh && sudo ufw default deny incoming && sudo ufw enable"
	}
}

// RemoveFlags describes the edit that takes an exposing flag out of a launch
// script, naming the line rather than changing it.
func RemoveFlags(path string, flags []string) string {
	return fmt.Sprintf("Open %s and delete %s from the launch line, then restart the interface.",
		path, humanList(flags))
}

// DeletePortForward is the one action with no command at all: it happens in a
// router's web interface, and no two routers agree on where.
func DeletePortForward(protocol string, externalPort int, internal string, internalPort int) string {
	return fmt.Sprintf(
		"In your router's admin page, find the port forwarding table and delete the rule sending %s port %d to %s:%d. "+
			"Turn UPnP off too if you did not create the rule yourself. For remote access use a VPN or an SSH tunnel instead.",
		strings.ToUpper(protocol), externalPort, internal, internalPort)
}

func humanList(items []string) string {
	switch len(items) {
	case 0:
		return "the flag"
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

// shellQuote wraps a path for a POSIX shell when it needs it.
func shellQuote(s string) string {
	if !strings.ContainsAny(s, " \t'\"$&|;()<>*?[]{}#~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
