package injector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

type waitCall struct {
	pid     int
	options int
}

type pokeCall struct {
	pid  int
	addr uintptr
	data []byte
}

type regsCall struct {
	pid  int
	regs unix.PtraceRegs
}

type mockSysCalls struct {
	attachPID     int
	attachErr     error
	detachCalled  bool
	pokeDataErr   error
	pokeDataCalls []pokeCall
	pokeTextErr   error
	pokeTextCalls []pokeCall
	getRegsErr    error
	getRegsRegs   unix.PtraceRegs
	getRegsCalls  int
	setRegsErr    error
	setRegsCalls  []regsCall
	contPID       int
	contSig       int
	contErr       error
	contCalls     int
	waitStatus    unix.WaitStatus
	waitRetPID    int
	waitErr       error
	waitCalls     []waitCall
}

func (m *mockSysCalls) PtraceGetRegs(pid int, regs *unix.PtraceRegs) error {
	m.getRegsCalls++
	if m.getRegsErr != nil {
		return m.getRegsErr
	}
	*regs = m.getRegsRegs
	return nil
}

func (m *mockSysCalls) PtraceSetRegs(pid int, regs *unix.PtraceRegs) error {
	m.setRegsCalls = append(m.setRegsCalls, regsCall{pid: pid, regs: *regs})
	return m.setRegsErr
}

func (m *mockSysCalls) PtraceAttach(pid int) error {
	m.attachPID = pid
	return m.attachErr
}

func (m *mockSysCalls) PtraceDetach(pid int) error {
	m.detachCalled = true
	return m.attachErr
}

func (m *mockSysCalls) PtracePokeData(pid int, addr uintptr, data []byte) (int, error) {
	m.pokeDataCalls = append(m.pokeDataCalls, pokeCall{pid: pid, addr: addr, data: data})
	return len(data), m.pokeDataErr
}

func (m *mockSysCalls) PtracePokeText(pid int, addr uintptr, data []byte) (int, error) {
	m.pokeTextCalls = append(m.pokeTextCalls, pokeCall{pid: pid, addr: addr, data: data})
	return len(data), m.pokeTextErr
}

func (m *mockSysCalls) PtraceCont(pid int, sig int) error {
	m.contPID = pid
	m.contSig = sig
	m.contCalls++
	return m.contErr
}

func (m *mockSysCalls) Wait4(pid int, status *unix.WaitStatus, options int, rusage *unix.Rusage) (int, error) {
	m.waitCalls = append(m.waitCalls, waitCall{pid: pid, options: options})
	if status != nil {
		*status = m.waitStatus
	}
	return m.waitRetPID, m.waitErr
}

func makeStoppedStatus(sig unix.Signal) unix.WaitStatus {
	return unix.WaitStatus((uint32(sig) << 8) | 0x7f)
}

func TestPtracer_GetRegs_PropagatesError(t *testing.T) {
	mock := &mockSysCalls{
		getRegsErr: unix.EPERM,
	}
	tracer := &ptracer{1234, mock}
	_, err := tracer.GetRegs()
	assert.Error(t, err)
	assert.ErrorIs(t, err, unix.EPERM)
}

func TestPtracer_GetRegs_ReturnRegs(t *testing.T) {
	expectedRegs := unix.PtraceRegs{
		Rip: 0xdeadbeef,
		Rdi: 0xcafebabe,
		Rsp: 0x12345678,
	}
	mock := &mockSysCalls{
		getRegsRegs: expectedRegs,
	}
	tracer := &ptracer{1234, mock}
	regs, err := tracer.GetRegs()
	assert.NoError(t, err)
	assert.Equal(t, 1, mock.getRegsCalls)
	assert.Equal(t, regs.Rip, expectedRegs.Rip)
}

func TestPtracer_WaitWrongSignal(t *testing.T) {
	mock := &mockSysCalls{
		waitStatus: makeStoppedStatus(unix.SIGSEGV),
		waitRetPID: 1234,
	}
	tracer := &ptracer{1234, mock}
	err := tracer.Wait()
	assert.Error(t, err)
}

func TestPtracer_Wait_SIGTRAP(t *testing.T) {
	mock := &mockSysCalls{
		waitStatus: makeStoppedStatus(unix.SIGTRAP),
		waitRetPID: 1234,
	}
	tracer := &ptracer{1234, mock}
	err := tracer.Wait()
	assert.NoError(t, err)
	assert.Len(t, mock.waitCalls, 1)
	assert.Equal(t, 1234, mock.waitCalls[0].pid)
}

func TestPtracer_Cont_CallsPtraceCont(t *testing.T) {
	mock := &mockSysCalls{}
	tracer := &ptracer{pid: 1234, sys: mock}
	err := tracer.Cont()
	assert.NoError(t, err)
	assert.Equal(t, 1, mock.contCalls)
	assert.Equal(t, 1234, mock.contPID)
	assert.Equal(t, 0, mock.contSig)
}

func TestPtracer_SetRegs_SetsRIPAndRDI(t *testing.T) {
	const (
		shellcodeAddr uintptr = 0x7f0000002000
		stringAddr    uintptr = 0x7f0000001000
	)
	mock := &mockSysCalls{}
	tracer := &ptracer{pid: 1234, sys: mock}
	regs := unix.PtraceRegs{
		Rip: uint64(shellcodeAddr),
		Rdi: uint64(stringAddr),
	}
	err := tracer.SetRegs(regs)
	assert.NoError(t, err)
	assert.Len(t, mock.setRegsCalls, 1)
}

func TestPtracer_PokeText_WriteShellcode(t *testing.T) {
	const baseAddr uintptr = 0x7f0000002000
	mock := &mockSysCalls{}
	tracer := &ptracer{pid: 1234, sys: mock}
	shellcode := []byte{
		0x48, 0x31, 0xc0, 0x48, 0x89, 0xc7, 0x48, 0x31,
		0xd2, 0x48, 0x31, 0xf6, 0x0f, 0x05, 0xc3, 0x90,
	}
	err := tracer.PokeText(baseAddr, shellcode)
	assert.NoError(t, err)
	assert.Len(t, mock.pokeTextCalls, 1)
	assert.Len(t, mock.pokeDataCalls, 0)
}

func TestPtracer_PokeData_WritePathWithnull(t *testing.T) {
	const baseAddr uintptr = 0x7f0000001000
	mock := &mockSysCalls{}
	tracer := &ptracer{pid: 1234, sys: mock}
	payload := append([]byte("/tmp/lib.so"), 0)
	err := tracer.PokeData(baseAddr, payload)
	assert.NoError(t, err)
	assert.Len(t, mock.pokeDataCalls, 1)
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
