//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// consoleIsOurs asks Windows how many processes are attached to this console.
// Exactly one means nothing else is waiting on it -- no cmd.exe, no PowerShell
// -- so the window belongs to us and will close with the process. That is the
// double-click case.
func consoleIsOurs() bool {
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleProcessList")
	if err := proc.Find(); err != nil {
		return false
	}
	var pids [8]uint32
	n, _, _ := proc.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return n == 1
}
