//go:build windows

package supply

import (
	"syscall"
	"unsafe"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procGetDriveType = kernel32.NewProc("GetDriveTypeW")
)

// DRIVE_FIXED from winbase.h.
const driveFixed = 3

// fixedDrives lists the local fixed disks.
//
// Network and removable drives are deliberately excluded. A ComfyUI unzipped to
// D:\ is common enough to be worth finding, but a stat against a mapped network
// share whose server is gone blocks for seconds, and a scan must never hang on
// hardware that is not there. GetDriveTypeW answers from the drive table
// without touching the device.
func fixedDrives() []string {
	var out []string
	for c := byte('C'); c <= 'Z'; c++ {
		root := string(c) + `:\`
		p, err := syscall.UTF16PtrFromString(root)
		if err != nil {
			continue
		}
		t, _, _ := procGetDriveType.Call(uintptr(unsafe.Pointer(p)))
		if t == driveFixed {
			out = append(out, root)
		}
	}
	return out
}
