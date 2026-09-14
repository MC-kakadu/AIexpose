//go:build windows

package checks

import (
	"strings"
	"syscall"
	"unsafe"
)

// Firewall state is read from the registry through the API, not by running
// reg.exe or PowerShell.
//
// Three reasons, in order of importance. An unsigned binary spawning
// powershell.exe to inspect the host is a behavioural detection trigger, and
// Kaspersky's System Watcher blocked an earlier build for that. Get-NetFirewallProfile
// returns nothing at all on machines where a third-party suite manages the
// firewall, which is exactly the case this check most needs to handle. And the
// registry values are DWORDs, so nothing here depends on the display language.
var profileKeys = []struct{ name, path string }{
	{"Domain", `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile`},
	{"Private", `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile`},
	{"Public", `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile`},
}

func firewallState() FirewallState {
	var enabled, disabled, unread []string
	for _, p := range profileKeys {
		v, ok := readFirewallDWORD(p.path, "EnableFirewall")
		switch {
		case !ok:
			unread = append(unread, p.name)
		case v == 0:
			disabled = append(disabled, p.name)
		default:
			enabled = append(enabled, p.name)
		}
	}

	switch {
	case len(disabled) > 0:
		return FirewallState{Known: true, Enabled: false,
			Detail: "Windows Defender Firewall is disabled for profile(s): " + strings.Join(disabled, ", ") +
				". If another security product manages your firewall instead, check that product's settings."}
	case len(enabled) > 0:
		return FirewallState{Known: true, Enabled: true,
			Detail: "Windows Defender Firewall is enabled for profile(s): " + strings.Join(enabled, ", ") + "."}
	}
	return FirewallState{Detail: "the firewall policy keys could not be read (" +
		strings.Join(unread, ", ") + "); a third-party security suite may be managing the firewall"}
}

func readFirewallDWORD(path, value string) (uint32, bool) {
	keyPath, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, false
	}
	var h syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, keyPath, 0, syscall.KEY_READ, &h); err != nil {
		return 0, false
	}
	defer syscall.RegCloseKey(h)

	name, err := syscall.UTF16PtrFromString(value)
	if err != nil {
		return 0, false
	}
	var (
		typ  uint32
		data uint32
		size = uint32(unsafe.Sizeof(data))
	)
	if err := syscall.RegQueryValueEx(h, name, nil, &typ,
		(*byte)(unsafe.Pointer(&data)), &size); err != nil {
		return 0, false
	}
	if typ != syscall.REG_DWORD {
		return 0, false
	}
	return data, true
}

func firewallFix() string {
	return "Re-enable Windows Defender Firewall for every profile (Set-NetFirewallProfile -All -Enabled True), " +
		"and remove any inbound allow rule you did not create deliberately."
}
