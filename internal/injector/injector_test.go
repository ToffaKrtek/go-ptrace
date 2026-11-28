//go:build linux && amd64

package injector

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// mockTracer implements the Tracer interface for injector orchestration tests (T33).
type mockTracer struct {
	attachErr  error
	detachCall bool
	mmapSizes  []int
	mmapAddr   uintptr
	mmapErr    error
	writes     []struct {
		addr uintptr
		data []byte
	}
	writeErr  error
	runArg    uintptr
	runAddr   uintptr
	runRet    uint64
	runErr    error
	runCalled bool
	nextAddr  uintptr
}

func (m *mockTracer) Attach() error { return m.attachErr }

func (m *mockTracer) Detach() error {
	m.detachCall = true
	return nil
}

// MmapExec returns a fresh, distinct address per call by default (so T2 is exercised).
func (m *mockTracer) MmapExec(size int) (uintptr, error) {
	m.mmapSizes = append(m.mmapSizes, size)
	if m.mmapErr != nil {
		return 0, m.mmapErr
	}
	if m.mmapAddr != 0 {
		return m.mmapAddr, nil
	}
	m.nextAddr += 0x1000
	return 0x7f0000000000 + m.nextAddr, nil
}

func (m *mockTracer) WriteMem(addr uintptr, data []byte) error {
	if m.writeErr != nil {
		return m.writeErr
	}
	m.writes = append(m.writes, struct {
		addr uintptr
		data []byte
	}{addr: addr, data: append([]byte(nil), data...)})
	return nil
}

func (m *mockTracer) ReadMem(addr uintptr, data []byte) error { return nil }

func (m *mockTracer) RunShellcode(addr uintptr, arg uintptr) (uint64, error) {
	m.runCalled = true
	m.runAddr = addr
	m.runArg = arg
	return m.runRet, m.runErr
}

func TestInjector_Orchestration(t *testing.T) {
	mock := &mockTracer{runRet: 0xabcdef}
	inj := &Injector{Tracer: mock}
	err := inj.Inject(1234, []byte{0xcc}, "/tmp/lib.so")
	assert.NoError(t, err)
	assert.True(t, mock.runCalled)
	assert.True(t, mock.detachCall, "must detach (T14)")
	// two distinct allocations for path and shellcode
	assert.Len(t, mock.mmapSizes, 2)
	assert.Len(t, mock.writes, 2)
	assert.Equal(t, mock.writes[0].data, append([]byte("/tmp/lib.so"), 0), "path must be NUL-terminated")
	// arg passed to RunShellcode is the path address, and shellcode runs at its own address
	assert.Equal(t, mock.writes[0].addr, mock.runArg)
	assert.Equal(t, mock.writes[1].addr, mock.runAddr)
}

// T2: if the tracer hands back the same address for both allocations, injection must abort.
func TestInjector_SameAddressGuard(t *testing.T) {
	mock := &mockTracer{mmapAddr: 0x7f00001000, runRet: 1}
	inj := &Injector{Tracer: mock}
	err := inj.Inject(1234, []byte{0xcc}, "/tmp/lib.so")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "share an address")
	assert.False(t, mock.runCalled, "must not run shellcode when addresses collide")
}

// T12: a NULL dlopen handle must be surfaced as an error, not success.
func TestInjector_DlopenReturnsNull(t *testing.T) {
	mock := &mockTracer{runRet: 0}
	inj := &Injector{Tracer: mock}
	err := inj.Inject(1234, []byte{0xcc}, "/tmp/lib.so")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "dlopen returned NULL")
}

func TestInjector_AttachEPERM(t *testing.T) {
	mock := &mockTracer{attachErr: unix.EPERM}
	inj := &Injector{Tracer: mock}
	err := inj.Inject(1234, []byte{0xcc}, "/tmp/lib.so")
	assert.Error(t, err)
	assert.False(t, mock.runCalled)
}

func TestInjector_WriteFailure(t *testing.T) {
	mock := &mockTracer{writeErr: errors.New("EIO")}
	inj := &Injector{Tracer: mock}
	err := inj.Inject(1234, []byte{0xcc}, "/tmp/lib.so")
	assert.Error(t, err)
	assert.True(t, mock.detachCall, "rollback detach must still run on partial failure (T14)")
	assert.False(t, mock.runCalled)
}

// T29: libPath validation.
func TestInjector_ValidateLibPath(t *testing.T) {
	inj := &Injector{Tracer: &mockTracer{runRet: 1}}

	err := inj.Inject(1234, []byte{0xcc}, "")
	assert.Error(t, err, "empty path rejected")

	err = inj.Inject(1234, []byte{0xcc}, "relative/lib.so")
	assert.Error(t, err, "relative path rejected (T30)")
	assert.Contains(t, err.Error(), "absolute")

	assert.NoError(t, validateLibPath("/tmp/lib.so"))
}

func TestInjector_EmptyShellcode(t *testing.T) {
	inj := &Injector{Tracer: &mockTracer{}}
	err := inj.Inject(1234, nil, "/tmp/lib.so")
	assert.Error(t, err)
}

// T32: when Logf is set, every pipeline stage must be reported.
func TestInjector_VerboseLogging(t *testing.T) {
	mock := &mockTracer{runRet: 0x1234}
	var lines []string
	inj := &Injector{Tracer: mock, Logf: func(format string, args ...any) {
		lines = append(lines, fmt.Sprintf(format, args...))
	}}

	assert.NoError(t, inj.Inject(1234, []byte{0xcc}, "/tmp/lib.so"))

	joined := strings.Join(lines, "\n")
	assert.Contains(t, joined, "attached to pid 1234")
	assert.Contains(t, joined, "for the library path")
	assert.Contains(t, joined, "for the shellcode")
	assert.Contains(t, joined, "hijacking RIP")
	assert.Contains(t, joined, "dlopen returned handle 0x1234")
}

// Without Logf the injector must stay silent and must not panic.
func TestInjector_SilentByDefault(t *testing.T) {
	inj := &Injector{Tracer: &mockTracer{runRet: 1}}
	assert.Nil(t, inj.Logf)
	assert.NoError(t, inj.Inject(1234, []byte{0xcc}, "/tmp/lib.so"))
}
