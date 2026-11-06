package injector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

type mockTracer struct {
	attachErr     error
	attachCalled  bool
	detachCalled  bool
	mmapCalls     []int
	pokeDataCalls []struct {
		addr uintptr
		data []byte
	}
	pokeTextCalls []struct {
		addr uintptr
		data []byte
	}
	getRegsCalled bool
	setRegsCalled bool
	setRegsRegs   unix.PtraceRegs
	contCalled    bool
	waitCalled    bool
}

func (m *mockTracer) Attach() error {
	m.attachCalled = true
	return m.attachErr
}

func (m *mockTracer) Detach() error {
	m.detachCalled = true
	return nil
}

func (m *mockTracer) Mmap(size int) (uintptr, error) {
	m.mmapCalls = append(m.mmapCalls, size)
	if len(m.mmapCalls) == 1 {
		return 0x7f0000001000, nil
	}
	return 0x7f0000002000, nil
}

func (m *mockTracer) PokeData(addr uintptr, data []byte) error {
	m.pokeDataCalls = append(m.pokeDataCalls, struct {
		addr uintptr
		data []byte
	}{addr: addr, data: data})
	return nil
}

func (m *mockTracer) PokeText(addr uintptr, shellcode []byte) error {
	m.pokeTextCalls = append(m.pokeTextCalls, struct {
		addr uintptr
		data []byte
	}{addr: addr, data: shellcode})
	return nil
}

func (m *mockTracer) GetRegs() (unix.PtraceRegs, error) {
	m.getRegsCalled = true
	return unix.PtraceRegs{Rip: 0x400000, Rsp: 0x7fffffff}, nil
}

func (m *mockTracer) SetRegs(regs unix.PtraceRegs) error {
	m.setRegsCalled = true
	m.setRegsRegs = regs
	return nil
}

func (m *mockTracer) Cont() error {
	m.contCalled = true
	return nil
}

func (m *mockTracer) Wait() error {
	m.waitCalled = true
	return nil
}

func TestInjectorInject_ORchestration(t *testing.T) {
	mock := &mockTracer{}
	inj := &injector{tracer: mock}
	shelcode := []byte{0xcc, 0x90}
	libPath := "/tmp/lib.so"
	err := inj.Inject(1234, shelcode, libPath)
	assert.NoError(t, err)
	assert.True(t, mock.attachCalled)
	assert.True(t, mock.detachCalled)
	assert.Len(t, mock.mmapCalls, 2)
	assert.Len(t, mock.pokeDataCalls, 1)
	assert.Len(t, mock.pokeTextCalls, 1)
	assert.True(t, mock.getRegsCalled)
	assert.True(t, mock.setRegsCalled)
	assert.True(t, mock.contCalled)
	assert.True(t, mock.waitCalled)
}

func TestInjectorAttachEPERM(t *testing.T) {
	mock := &mockTracer{attachErr: unix.EPERM}
	inj := &injector{tracer: mock}
	err := inj.Inject(1234, []byte{}, "")
	assert.Error(t, err)
}
