//go:build windows

package netstat

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/MC-kakadu/AIexpose/internal/model"
)

// Windows socket enumeration goes straight to the IP Helper API rather than
// shelling out to PowerShell or netstat.
//
// The reason is behavioural detection, not speed. An unsigned executable that
// spawns powershell.exe to enumerate the host is one of the strongest signals a
// behaviour engine looks for, and Kaspersky's System Watcher blocked an earlier
// build of this tool for exactly that shape of activity. Calling the API in
// process spawns nothing, so there is no child process to notice. It is also
// immune to the localisation and execution-policy problems that made the shell
// path unreliable.
const (
	afINet  = 2
	afINet6 = 23

	// TCP_TABLE_OWNER_PID_LISTENER
	tcpTableOwnerPIDListener = 3

	errInsufficientBuffer = 122
	maxTableBytes         = 8 << 20
)

var (
	iphlpapi           = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTCP = iphlpapi.NewProc("GetExtendedTcpTable")
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procCreateSnapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First = kernel32.NewProc("Process32FirstW")
	procProcess32Next  = kernel32.NewProc("Process32NextW")
)

// mibTCPRowOwnerPID mirrors MIB_TCPROW_OWNER_PID.
type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

// mibTCP6RowOwnerPID mirrors MIB_TCP6ROW_OWNER_PID.
type mibTCP6RowOwnerPID struct {
	LocalAddr     [16]byte
	LocalScopeID  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeID uint32
	RemotePort    uint32
	State         uint32
	OwningPID     uint32
}

func listeners() ([]model.Listener, error) {
	names := processNames()

	out, err4 := listenersFor(afINet, names)
	v6, err6 := listenersFor(afINet6, names)
	out = append(out, v6...)

	if len(out) == 0 && err4 != nil && err6 != nil {
		// Every API path failed. Fall back to parsing netstat so a scan still
		// produces something, accepting the child process in that one case.
		return fallbackNetstat()
	}
	return out, nil
}

func listenersFor(family uintptr, names map[int]string) ([]model.Listener, error) {
	buf, err := tcpTable(family)
	if err != nil {
		return nil, err
	}
	if len(buf) < 4 {
		return nil, nil
	}
	count := int(binary.LittleEndian.Uint32(buf[:4]))

	var (
		rowSize = int(unsafe.Sizeof(mibTCPRowOwnerPID{}))
		out     []model.Listener
	)
	if family == afINet6 {
		rowSize = int(unsafe.Sizeof(mibTCP6RowOwnerPID{}))
	}
	// The rows begin after dwNumEntries, on the struct's own alignment.
	offset := int(unsafe.Sizeof(uint32(0)))
	if family == afINet6 {
		offset = 4
	}

	for i := 0; i < count; i++ {
		start := offset + i*rowSize
		if start+rowSize > len(buf) {
			break
		}
		var (
			addr string
			port int
			pid  int
			v6   bool
		)
		if family == afINet6 {
			row := (*mibTCP6RowOwnerPID)(unsafe.Pointer(&buf[start]))
			ip := make(net.IP, 16)
			copy(ip, row.LocalAddr[:])
			addr, port, pid, v6 = ip.String(), netPort(row.LocalPort), int(row.OwningPID), true
		} else {
			row := (*mibTCPRowOwnerPID)(unsafe.Pointer(&buf[start]))
			var ip [4]byte
			binary.LittleEndian.PutUint32(ip[:], row.LocalAddr)
			addr, port, pid = net.IPv4(ip[0], ip[1], ip[2], ip[3]).String(), netPort(row.LocalPort), int(row.OwningPID)
		}
		out = append(out, model.Listener{
			Addr: addr, Port: port, PID: pid, Process: names[pid], IPv6: v6,
		})
	}
	return out, nil
}

// tcpTable asks for the listener table, growing the buffer until it fits.
func tcpTable(family uintptr) ([]byte, error) {
	var size uint32
	r, _, _ := procGetExtendedTCP.Call(0, uintptr(unsafe.Pointer(&size)), 0,
		family, tcpTableOwnerPIDListener, 0)
	if r != errInsufficientBuffer && r != 0 {
		return nil, syscall.Errno(r)
	}
	for attempt := 0; attempt < 4; attempt++ {
		if size == 0 || size > maxTableBytes {
			return nil, nil
		}
		buf := make([]byte, size)
		r, _, _ := procGetExtendedTCP.Call(uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)), 0, family, tcpTableOwnerPIDListener, 0)
		switch r {
		case 0:
			return buf, nil
		case errInsufficientBuffer:
			continue // the table grew between calls; size was updated
		default:
			return nil, syscall.Errno(r)
		}
	}
	return nil, nil
}

// netPort reads the port from a DWORD that holds it in network byte order.
func netPort(v uint32) int {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return int(b[0])<<8 | int(b[1])
}

// processEntry32 mirrors PROCESSENTRY32W.
type processEntry32 struct {
	Size            uint32
	CntUsage        uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	CntThreads      uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

// processNames snapshots every process name in one call. Unlike opening each
// process individually, this reads no other process's memory and needs no
// elevated rights.
func processNames() map[int]string {
	const th32csSnapProcess = 0x00000002
	m := map[int]string{}

	h, _, _ := procCreateSnapshot.Call(th32csSnapProcess, 0)
	if h == 0 || h == uintptr(syscall.InvalidHandle) {
		return m
	}
	defer syscall.CloseHandle(syscall.Handle(h))

	var e processEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	r, _, _ := procProcess32First.Call(h, uintptr(unsafe.Pointer(&e)))
	for r != 0 {
		m[int(e.ProcessID)] = syscall.UTF16ToString(e.ExeFile[:])
		r, _, _ = procProcess32Next.Call(h, uintptr(unsafe.Pointer(&e)))
	}
	return m
}

// fallbackNetstat is used only when the API path fails entirely. Listening rows
// are identified by their foreign address rather than the state word, which is
// localised on non-English Windows.
func fallbackNetstat() ([]model.Listener, error) {
	out, err := run("netstat", "-ano", "-p", "TCP")
	if err != nil {
		return nil, err
	}
	var res []model.Listener
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || !strings.EqualFold(f[0], "TCP") || !strings.HasSuffix(f[2], ":0") {
			continue
		}
		addr, port, v6, ok := splitHostPort(f[1])
		if !ok {
			continue
		}
		pid, _ := strconv.Atoi(f[len(f)-1])
		res = append(res, model.Listener{Addr: addr, Port: port, PID: pid, IPv6: v6})
	}
	return res, nil
}

func splitHostPort(s string) (string, int, bool, bool) {
	s = strings.TrimSpace(s)
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", 0, false, false
	}
	host, portStr := s[:i], s[i+1:]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, false, false
	}
	v6 := strings.HasPrefix(host, "[")
	return strings.Trim(host, "[]"), port, v6, true
}
