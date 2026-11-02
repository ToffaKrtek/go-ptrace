package injector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type pokeCall struct {
	pid  int
	addr uintptr
	data uintptr
}

type mockSysCalls struct {
	attachPID     int
	attachErr     error
	detachCalled  bool
	pokeDataErr   error
	pokeDataCalls []pokeCall
	pokeTextErr   error
	pokeTextCalls []pokeCall
}

func (m *mockSysCalls) PtraceAttach(pid int) error {
	m.attachPID = pid
	return m.attachErr
}

func (m *mockSysCalls) PtraceDetach(pid int) error {
	m.detachCalled = true
	return m.attachErr
}

func (m *mockSysCalls) PtracePokeData(pid int, addr uintptr, data uintptr) error {
	m.pokeDataCalls = append(m.pokeDataCalls, pokeCall{pid: pid, addr: addr, data: data})
	return m.pokeDataErr
}

func (m *mockSysCalls) PtracePokeText(pid int, addr uintptr, data uintptr) error {
	m.pokeTextCalls = append(m.pokeTextCalls, pokeCall{pid: pid, addr: addr, data: data})
	return m.pokeTextErr
}

func TestPtacer_PokeText_WriteShellcode(t *testing.T) {
	const baseAddr uintptr = 0x7f0000002000
	mock := &mockSysCalls{}
	tracer := &ptracer{pid: 1234, sys: mock}
	shellcode := []byte{
		0x48, 0x31, 0xc0, 0x48, 0x89, 0xc7, 0x48, 0x31,
		0xd2, 0x48, 0x31, 0xf6, 0x0f, 0x05, 0xc3, 0x90,
	}
	err := tracer.PokeText(baseAddr, shellcode)
	assert.NoError(t, err)
	assert.Len(t, mock.pokeTextCalls, 2)
	assert.Len(t, mock.pokeDataCalls, 0)
}

func TestPtracer_PokeData_WritePathWithnull(t *testing.T) {
	const baseAddr uintptr = 0x7f0000001000
	mock := &mockSysCalls{}
	tracer := &ptracer{pid: 1234, sys: mock}
	payload := append([]byte("/tmp/lib.so"), 0)
	err := tracer.PokeData(baseAddr, payload)
	assert.NoError(t, err)
	assert.Len(t, mock.pokeDataCalls, 2)
	c0 := mock.pokeDataCalls[0]
	assert.Equal(t, c0.pid, 1234)
	assert.Equal(t, c0.addr, baseAddr)
}

func TestTracer_Attach_Success(t *testing.T) {
	mock := &mockSysCalls{}
	tracer := &ptracer{
		pid: 1234,
		sys: mock,
	}
	err := tracer.Attach()
	assert.NoError(t, err)
	assert.Equal(t, mock.attachPID, 1234)
}

func TestTracer_Detach(t *testing.T) {
	mock := &mockSysCalls{}
	tracer := &ptracer{
		pid: 1234,
		sys: mock,
	}
	err := tracer.Detach()
	assert.NoError(t, err)
	assert.True(t, mock.detachCalled)
}

func TestPtracer_Mmap_Success(t *testing.T) {
	tracer := &ptracer{pid: 1234, sys: &mockSysCalls{}}
	addr, err := tracer.Mmap(4096)
	assert.NoError(t, err)
	assert.NotEqual(t, addr, ^uintptr(0))
}

func TestPtracer_Mmap_InvalidSize(t *testing.T) {
	tracer := &ptracer{pid: 1234, sys: &mockSysCalls{}}
	addr, err := tracer.Mmap(0)
	assert.Error(t, err)
	assert.Equal(t, addr, ^uintptr(0))
}
