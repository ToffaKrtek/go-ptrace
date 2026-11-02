package injector

import (
	"encoding/binary"
	"errors"
)

const (
	MAP_FAILED = ^uintptr(0)
	MAP_OK     = 0x7f0000000000
	wordSize   = 8
)

type sysCalls interface {
	PtraceAttach(pid int) error
	PtraceDetach(pid int) error
	PtracePokeData(pid int, addr uintptr, data uintptr) error
	PtracePokeText(pid int, addr uintptr, data uintptr) error
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
	return p.writeWords(addr, data, func(a, w uintptr) error {
		return p.sys.PtracePokeData(p.pid, a, w)
	})
}

func (p *ptracer) PokeText(addr uintptr, shellcode []byte) error {
	return p.writeWords(addr, shellcode, func(a, w uintptr) error {
		return p.sys.PtracePokeText(p.pid, a, w)
	})
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
