//go:build linux && amd64

package injector

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type unixSysCalls struct{}

func (u *unixSysCalls) PtraceAttach(pid int) error {
	return unix.PtraceAttach(pid)
}

func (u *unixSysCalls) PtraceDetach(pid int) error {
	return unix.PtraceDetach(pid)
}

func (u *unixSysCalls) PtracePokeData(pid int, addr uintptr, data []byte) (int, error) {
	return unix.PtracePokeData(pid, addr, data)
}

func (u *unixSysCalls) PtracePokeText(pid int, addr uintptr, data []byte) (int, error) {
	return unix.PtracePokeText(pid, addr, data)
}

func (u *unixSysCalls) PtracePeekData(pid int, addr uintptr, out []byte) (int, error) {
	return unix.PtracePeekData(pid, addr, out)
}

func (u *unixSysCalls) PtracePeekText(pid int, addr uintptr, out []byte) (int, error) {
	return unix.PtracePeekText(pid, addr, out)
}

func (u *unixSysCalls) PtraceGetRegs(pid int, regs *unix.PtraceRegs) error {
	return unix.PtraceGetRegs(pid, regs)
}

func (u *unixSysCalls) PtraceSetRegs(pid int, regs *unix.PtraceRegs) error {
	return unix.PtraceSetRegs(pid, regs)
}

func (u *unixSysCalls) PtraceCont(pid int, sig int) error {
	return unix.PtraceCont(pid, sig)
}

func (u *unixSysCalls) PtraceSetOptions(pid int, options int) error {
	return unix.PtraceSetOptions(pid, options)
}

func (u *unixSysCalls) Wait4(pid int, status *unix.WaitStatus, options int, rusage *unix.Rusage) (int, error) {
	return unix.Wait4(pid, status, options, rusage)
}

func (u *unixSysCalls) ListTIDs(pid int) ([]int, error) {
	return listTIDs(pid)
}

func (u *unixSysCalls) ReadMaps(pid int) ([]byte, error) {
	return os.ReadFile("/proc/" + strconv.Itoa(pid) + "/maps")
}

func (u *unixSysCalls) ReadStatus(pid int) ([]byte, error) {
	return os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
}

// procYamaScope is the sysctl knob that restricts which processes may be ptraced.
const procYamaScope = "/proc/sys/kernel/yama/ptrace_scope"

// ReadPtraceScope reports the Yama ptrace_scope value, or -1 when Yama is not present
// (the file is optional and absent on kernels configured without it).
func (u *unixSysCalls) ReadPtraceScope() (int, error) {
	data, err := os.ReadFile(procYamaScope)
	if err != nil {
		return -1, err
	}
	scope, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return -1, fmt.Errorf("parse %s: %w", procYamaScope, err)
	}
	return scope, nil
}
