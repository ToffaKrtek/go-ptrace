package injector

import (
	"encoding/binary"
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

func wordToBytes(w uintptr) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(w))
	return b
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
