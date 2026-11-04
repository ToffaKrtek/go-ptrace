package injector

import "golang.org/x/sys/unix"

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

func (u *unixSysCalls) PtraceGetRegs(pid int, regs *unix.PtraceRegs) error {
	return unix.PtraceGetRegs(pid, regs)
}

func (u *unixSysCalls) PtraceSetRegs(pid int, regs *unix.PtraceRegs) error {
	return unix.PtraceSetRegs(pid, regs)
}

func (u *unixSysCalls) PtraceCont(pid int, sig int) error {
	return unix.PtraceCont(pid, sig)
}

func (u *unixSysCalls) Wait4(pid int, status *unix.WaitStatus, options int, rusage *unix.Rusage) (int, error) {
	return unix.Wait4(pid, status, options, rusage)
}

func NewTracer(pid int) Tracer {
	return &ptracer{
		pid: pid,
		sys: &unixSysCalls{},
	}
}
