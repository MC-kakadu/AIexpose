//go:build windows

package browse

import (
	"fmt"
	"syscall"
	"unsafe"
)

// swShowNormal asks for an ordinary window rather than a hidden one. Hidden
// windows are what malware asks for, and endpoint protection knows it.
const swShowNormal = 1

// shellExecuteMinSuccess: ShellExecuteW returns a value greater than 32 on
// success, and a small error code otherwise. The API is that old.
const shellExecuteMinSuccess = 32

func open(path string) error {
	shell32 := syscall.NewLazyDLL("shell32.dll")
	proc := shell32.NewProc("ShellExecuteW")
	if err := proc.Find(); err != nil {
		return err
	}

	verb, err := syscall.UTF16PtrFromString("open")
	if err != nil {
		return err
	}
	file, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	r, _, callErr := proc.Call(
		0, // no parent window
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		0, // no parameters
		0, // no working directory
		swShowNormal,
	)
	if r <= shellExecuteMinSuccess {
		if callErr != nil && r == 0 {
			return callErr
		}
		return fmt.Errorf("the shell declined to open the file (code %d)", r)
	}
	return nil
}
