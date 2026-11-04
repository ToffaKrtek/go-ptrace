package injector

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

const (
	MAP_FAILED = ^uintptr(0)
	MAP_OK     = 0x7f0000000000
	wordSize   = 8
)

type sysCalls interface {
	PtraceAttach(pid int) error
	PtraceDetach(pid int) error
	PtracePokeData(pid int, addr uintptr, data []byte) (int, error)
	PtracePokeText(pid int, addr uintptr, data []byte) (int, error)
	PtraceGetRegs(pid int, regs *unix.PtraceRegs) error
	PtraceSetRegs(pid int, regs *unix.PtraceRegs) error
	PtraceCont(pid int, sig int) error
	Wait4(pid int, status *unix.WaitStatus, options int, rusage *unix.Rusage) (int, error)
}

type Tracer interface {
	Attach() error
	Detach() error
}

type ptracer struct {
	pid int
	sys sysCalls
}

func (t *ptracer) Attach() error {
	return t.sys.PtraceAttach(t.pid)
}

func (t *ptracer) Detach() error {
	return t.sys.PtraceDetach(t.pid)
}

func (p *ptracer) Mmap(size int) (uintptr, error) {
	if size <= 0 {
		return MAP_FAILED, errors.New("invalid mmap size")
	}
	return MAP_OK, nil
}

func (p *ptracer) PokeData(addr uintptr, data []byte) error {
	_, err := p.sys.PtracePokeData(p.pid, addr, data)
	return err
	// return p.writeWords(addr, data, func(a, w uintptr) (int, error) {
	// 	return p.sys.PtracePokeData(p.pid, a, w)
	// })
}

func (p *ptracer) PokeText(addr uintptr, shellcode []byte) error {
	_, err := p.sys.PtracePokeText(p.pid, addr, shellcode)
	return err
	// return p.writeWords(addr, shellcode, func(a, w uintptr) (int, error) {
	// 	return p.sys.PtracePokeText(p.pid, a, w)
	// })
}

func (p *ptracer) writeWords(addr uintptr, data []byte, writer func(uintptr, uintptr) error) error {
	for i := 0; i < len(data); i += wordSize {
		buf := make([]byte, wordSize)
		end := i + wordSize
		if end > len(data) {
			end = len(data)
		}
		copy(buf, data[i:end])
		word := uintptr(binary.LittleEndian.Uint64(buf))
		if err := writer(addr+uintptr(i), word); err != nil {
			return err
		}
	}
	return nil
}

func (p *ptracer) SetRegs(regs unix.PtraceRegs) error {
	return p.sys.PtraceSetRegs(p.pid, &regs)
}

func (p *ptracer) GetRegs() (unix.PtraceRegs, error) {
	var regs unix.PtraceRegs
	err := p.sys.PtraceGetRegs(p.pid, &regs)
	return regs, err
}

func (p *ptracer) Cont() error {
	return p.sys.PtraceCont(p.pid, 0)
}

func (p *ptracer) Wait() error {
	var status unix.WaitStatus
	if _, err := p.sys.Wait4(p.pid, &status, 0, nil); err != nil {
		return err
	}
	if !status.Stopped() {
		return errors.New("process not stopped (exited or signaled)")
	}
	if status.StopSignal() != unix.SIGTRAP {
		return fmt.Errorf("unexpected stop signal: %v", status.StopSignal())
	}
	return nil
}
