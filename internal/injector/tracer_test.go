//go:build linux && amd64

package injector

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// --- mock sysCalls ---

type pokeCall struct {
	pid  int
	addr uintptr
	data []byte
}

type waitCall struct {
	pid     int
	options int
}

type contCall struct {
	pid int
	sig int
}

type setOptCall struct {
	pid  int
	opts int
}

type mockSysCalls struct {
	tids    []int
	tidsErr error
	maps    []byte
	mapsErr error

	status    []byte
	statusErr error
	scope     int
	scopeErr  error

	attachErr       map[int]error
	attachCalls     []int
	detachCalls     []int
	setOptionsCalls []setOptCall

	waitStatuses []unix.WaitStatus
	waitErr      error
	waitIdx      int
	waitCalls    []waitCall
	// waitNoChild makes Wait4 behave like "no child changed state yet" (WNOHANG).
	waitNoChild bool

	getRegsQueue   []unix.PtraceRegs
	getRegsIdx     int
	getRegsDefault unix.PtraceRegs
	setRegsCalls   []unix.PtraceRegs

	peekData  []byte
	peekErr   error
	pokeData  []pokeCall
	pokeText  []pokeCall
	pokeErr   error
	pokeShort bool
	contCalls []contCall
	contErr   error
}

func (m *mockSysCalls) PtraceAttach(pid int) error {
	m.attachCalls = append(m.attachCalls, pid)
	if e, ok := m.attachErr[pid]; ok {
		return e
	}
	return nil
}

func (m *mockSysCalls) PtraceDetach(pid int) error {
	m.detachCalls = append(m.detachCalls, pid)
	return nil
}

func (m *mockSysCalls) PtraceSetOptions(pid, options int) error {
	m.setOptionsCalls = append(m.setOptionsCalls, setOptCall{pid: pid, opts: options})
	return nil
}

func (m *mockSysCalls) ListTIDs(int) ([]int, error)  { return m.tids, m.tidsErr }
func (m *mockSysCalls) ReadMaps(int) ([]byte, error) { return m.maps, m.mapsErr }

func (m *mockSysCalls) ReadStatus(int) ([]byte, error) { return m.status, m.statusErr }

func (m *mockSysCalls) ReadPtraceScope() (int, error) {
	if m.scopeErr != nil {
		return -1, m.scopeErr
	}
	return m.scope, nil
}

func (m *mockSysCalls) Wait4(pid int, status *unix.WaitStatus, options int, _ *unix.Rusage) (int, error) {
	m.waitCalls = append(m.waitCalls, waitCall{pid: pid, options: options})
	if m.waitErr != nil {
		return 0, m.waitErr
	}
	if m.waitNoChild {
		return 0, nil
	}
	var st unix.WaitStatus
	switch {
	case m.waitIdx < len(m.waitStatuses):
		st = m.waitStatuses[m.waitIdx]
		m.waitIdx++
	case len(m.waitStatuses) > 0:
		st = m.waitStatuses[len(m.waitStatuses)-1]
	}
	if status != nil {
		*status = st
	}
	return pid, nil
}

func (m *mockSysCalls) PtraceGetRegs(_ int, regs *unix.PtraceRegs) error {
	if m.getRegsIdx < len(m.getRegsQueue) {
		*regs = m.getRegsQueue[m.getRegsIdx]
		m.getRegsIdx++
	} else {
		*regs = m.getRegsDefault
	}
	return nil
}

func (m *mockSysCalls) PtraceSetRegs(_ int, regs *unix.PtraceRegs) error {
	m.setRegsCalls = append(m.setRegsCalls, *regs)
	return nil
}

func (m *mockSysCalls) PtracePeekData(_ int, _ uintptr, out []byte) (int, error) {
	if m.peekErr != nil {
		return 0, m.peekErr
	}
	return copy(out, m.peekData), nil
}

func (m *mockSysCalls) PtracePeekText(_ int, _ uintptr, out []byte) (int, error) {
	if m.peekErr != nil {
		return 0, m.peekErr
	}
	return copy(out, m.peekData), nil
}

func (m *mockSysCalls) PtracePokeData(_ int, addr uintptr, data []byte) (int, error) {
	m.pokeData = append(m.pokeData, pokeCall{addr: addr, data: append([]byte(nil), data...)})
	if m.pokeErr != nil {
		return 0, m.pokeErr
	}
	if m.pokeShort {
		return len(data) - 1, nil
	}
	return len(data), nil
}

func (m *mockSysCalls) PtracePokeText(_ int, addr uintptr, data []byte) (int, error) {
	m.pokeText = append(m.pokeText, pokeCall{addr: addr, data: append([]byte(nil), data...)})
	if m.pokeErr != nil {
		return 0, m.pokeErr
	}
	if m.pokeShort {
		return len(data) - 1, nil
	}
	return len(data), nil
}

func (m *mockSysCalls) PtraceCont(pid int, sig int) error {
	m.contCalls = append(m.contCalls, contCall{pid: pid, sig: sig})
	return m.contErr
}

// --- wait-status builders ---

func stoppedStatus(sig unix.Signal) unix.WaitStatus {
	return unix.WaitStatus((uint32(sig) << 8) | 0x7f)
}
func exitedStatus(code int) unix.WaitStatus          { return unix.WaitStatus(uint32(code) << 8) }
func signaledStatus(sig unix.Signal) unix.WaitStatus { return unix.WaitStatus(uint32(sig)) }

var sampleMaps = []byte(
	"555555554000-555555555000 r-xp 00000000 08:01 1 /usr/bin/sleep\n" +
		"7f5a46024000-7f5a4619f000 r-xp 00024000 00:1d 3427 /usr/lib/libc.so.6\n" +
		"7fb3ecc1b000-7fb3ecc1c000 rw-p 00000000 00:00 0\n")

func attachedPtracer(mock *mockSysCalls) *ptracer {
	return &ptracer{
		pid:         1234,
		sys:         mock,
		waitTimeout: DefaultWaitTimeout,
		attached:    true,
		tids:        []int{1234},
		savedRegs:   &unix.PtraceRegs{Rip: 0x400000, Rsp: 0x7ffffff00000},
	}
}

// T13/T8/T9: Attach must stop every LWP and wait for each group-stop.
func TestPtracer_Attach_StopsAllLWPs(t *testing.T) {
	mock := &mockSysCalls{
		tids:           []int{1234, 1235, 1236},
		waitStatuses:   []unix.WaitStatus{stoppedStatus(unix.SIGSTOP), stoppedStatus(unix.SIGSTOP), stoppedStatus(unix.SIGSTOP)},
		getRegsDefault: unix.PtraceRegs{Rip: 0x400000},
	}
	p := &ptracer{pid: 1234, sys: mock}
	err := p.Attach()
	assert.NoError(t, err)
	assert.Equal(t, []int{1234, 1235, 1236}, mock.attachCalls, "must attach to every LWP")
	assert.Len(t, mock.setOptionsCalls, 3, "must set EXITKILL on every LWP (T15)")
	for _, so := range mock.setOptionsCalls {
		assert.Equal(t, unix.PTRACE_O_EXITKILL, so.opts)
	}
	assert.True(t, p.attached)
	assert.NotNil(t, p.savedRegs)
}

// T14: on a failed attach, already-attached LWPs must be rolled back.
func TestPtracer_Attach_RollbackOnFailure(t *testing.T) {
	mock := &mockSysCalls{
		tids:         []int{1234, 1235},
		attachErr:    map[int]error{1235: unix.EPERM},
		waitStatuses: []unix.WaitStatus{stoppedStatus(unix.SIGSTOP)},
	}
	p := &ptracer{pid: 1234, sys: mock}
	err := p.Attach()
	assert.Error(t, err)
	assert.Contains(t, mock.detachCalls, 1234, "must detach the tid we already stopped")
	assert.False(t, p.attached)
}

func TestPtracer_Attach_EmptyTIDs(t *testing.T) {
	mock := &mockSysCalls{tids: nil}
	p := &ptracer{pid: 1234, sys: mock}
	err := p.Attach()
	assert.Error(t, err)
}

// T10/T7: Detach restores gate bytes and the saved registers, then releases LWPs.
func TestPtracer_Detach_RestoresState(t *testing.T) {
	mock := &mockSysCalls{}
	p := attachedPtracer(mock)
	p.gateAddr = 0x555555554100
	p.gateBackup = []byte{0xde, 0xad, 0xbe, 0xef, 0x11, 0x22, 0x33, 0x44}
	err := p.Detach()
	assert.NoError(t, err)
	// gate bytes restored (T10)
	gatePoke := false
	for _, pc := range mock.pokeText {
		if pc.addr == 0x555555554100 {
			assert.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef, 0x11, 0x22, 0x33, 0x44}, pc.data)
			gatePoke = true
		}
	}
	assert.True(t, gatePoke, "gate bytes must be restored (T10)")
	// saved registers restored (T7)
	assert.NotEmpty(t, mock.setRegsCalls, "registers must be restored (T7)")
	assert.Equal(t, uint64(0x400000), mock.setRegsCalls[len(mock.setRegsCalls)-1].Rip)
	assert.Equal(t, []int{1234}, mock.detachCalls)
}

func TestPtracer_Detach_NotAttached(t *testing.T) {
	p := &ptracer{pid: 1234, sys: &mockSysCalls{}}
	assert.Error(t, p.Detach())
}

// T1/T2/T21: MmapExec runs a remote mmap syscall through a planted gate.
func TestPtracer_MmapExec_PlantsGateAndCallsSyscall(t *testing.T) {
	mock := &mockSysCalls{
		maps:         sampleMaps,
		peekData:     []byte{0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xe4, 0xf0}, // original bytes
		waitStatuses: []unix.WaitStatus{stoppedStatus(unix.SIGTRAP)},
		getRegsQueue: []unix.PtraceRegs{
			{Rip: 0x400000, Rsp: 0x7ffffff00000, Rax: 0x999}, // orig before hijack
			{Rax: 0x7f00001000}, // RAX after mmap
		},
	}
	p := attachedPtracer(mock)

	addr, err := p.MmapExec(100)
	assert.NoError(t, err)
	assert.Equal(t, uintptr(0x7f00001000), addr)

	// gate planted in the first r-xp region
	if assert.NotEmpty(t, mock.pokeText) {
		assert.Equal(t, uintptr(0x555555554000), mock.pokeText[0].addr)
		assert.Equal(t, []byte{0x0f, 0x05, 0xcc, 0x90, 0x90, 0x90, 0x90, 0x90}, mock.pokeText[0].data,
			"gate must be 'syscall; int3; nop*5'")
	}
	// syscall args: mmap(0, 4096, PROT_READ|WRITE|EXEC, MAP_PRIVATE|ANON, -1, 0)
	if assert.GreaterOrEqual(t, len(mock.setRegsCalls), 1) {
		setup := mock.setRegsCalls[0]
		assert.Equal(t, uint64(unix.SYS_MMAP), setup.Rax)
		assert.Equal(t, uint64(4096), setup.Rsi, "size must be page-rounded")
		assert.Equal(t, uint64(unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC), setup.Rdx, "must be executable (T1)")
		assert.Equal(t, uint64(unix.MAP_PRIVATE|unix.MAP_ANONYMOUS), setup.R10)
		assert.Equal(t, ^uint64(0), setup.R8, "fd must be -1")
		assert.Equal(t, uint64(0x555555554000), setup.Rip)
		// ORIG_RAX cleared so the kernel cannot restart an interrupted syscall
		// and rewind RIP by 2 on resume (regression guard).
		assert.Equal(t, ^uint64(0), setup.Orig_rax)
	}
	// registers restored to the pre-hijack snapshot
	assert.Equal(t, uint64(0x999), mock.setRegsCalls[len(mock.setRegsCalls)-1].Rax, "regs must be restored")
	assert.Equal(t, p.gateAddr, uintptr(0x555555554000))
}

// T21: a syscall error (-errno) must surface as an error, not a bogus address.
// negErrno encodes a syscall return of -errno as it would appear in RAX.
func negErrno(e unix.Errno) uint64 { return uint64(int64(-int(e))) }

func TestPtracer_MmapExec_SyscallError(t *testing.T) {
	mock := &mockSysCalls{
		maps:         sampleMaps,
		peekData:     []byte{0, 0, 0, 0, 0, 0, 0, 0},
		waitStatuses: []unix.WaitStatus{stoppedStatus(unix.SIGTRAP)},
		getRegsQueue: []unix.PtraceRegs{
			{Rip: 0x400000},
			{Rax: negErrno(unix.ENOMEM)},
		},
	}
	p := attachedPtracer(mock)
	_, err := p.MmapExec(4096)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mmap failed")
}

func TestPtracer_MmapExec_InvalidSize(t *testing.T) {
	p := attachedPtracer(&mockSysCalls{maps: sampleMaps})
	_, err := p.MmapExec(0)
	assert.Error(t, err)
	_, err = p.MmapExec(-5)
	assert.Error(t, err)
}

func TestPtracer_MmapExec_NotAttached(t *testing.T) {
	p := &ptracer{pid: 1234, sys: &mockSysCalls{}}
	_, err := p.MmapExec(4096)
	assert.Error(t, err)
}

// RunShellcode: hijack RIP, capture RAX, restore registers.
func TestPtracer_RunShellcode_Success(t *testing.T) {
	mock := &mockSysCalls{
		waitStatuses: []unix.WaitStatus{stoppedStatus(unix.SIGTRAP)},
		getRegsQueue: []unix.PtraceRegs{
			{Rip: 0x400000, Rsp: 0x7ffffff00000, Rax: 0x111},
			{Rax: 0xdeadbeef}, // dlopen handle
		},
	}
	p := attachedPtracer(mock)
	ret, err := p.RunShellcode(0x7f00002000, 0x7f00001000)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0xdeadbeef), ret)
	// first setRegs: RIP=shellcode, RDI=path
	assert.Equal(t, uint64(0x7f00002000), mock.setRegsCalls[0].Rip)
	assert.Equal(t, uint64(0x7f00001000), mock.setRegsCalls[0].Rdi)
	// ORIG_RAX must be cleared to -1, otherwise the kernel's syscall-restart path
	// rewinds RIP by 2 on resume and the target dies with SIGSEGV (regression guard).
	assert.Equal(t, ^uint64(0), mock.setRegsCalls[0].Orig_rax)
	// last setRegs: restore original RIP
	assert.Equal(t, uint64(0x400000), mock.setRegsCalls[len(mock.setRegsCalls)-1].Rip)
	// Cont with signal 0 (T11)
	assert.Equal(t, []contCall{{pid: 1234, sig: 0}}, mock.contCalls)
}

// T18: a target that dies or takes an unexpected signal must be reported distinctly.
func TestPtracer_RunShellcode_TargetDied(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  unix.WaitStatus
		wantSub string
	}{
		{"segv", signaledStatus(unix.SIGSEGV), "signal"},
		{"exit", exitedStatus(3), "exited"},
		{"wrong-stop", stoppedStatus(unix.SIGSTOP), "unexpected stop"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockSysCalls{
				waitStatuses: []unix.WaitStatus{tc.status},
				getRegsQueue: []unix.PtraceRegs{
					{Rip: 0x400000, Rax: 0x111},
					{Rax: 0},
				},
			}
			p := attachedPtracer(mock)
			_, err := p.RunShellcode(0x7f00002000, 0x7f00001000)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantSub)
			// registers must still be restored on failure (T7/T14)
			assert.Equal(t, uint64(0x400000), mock.setRegsCalls[len(mock.setRegsCalls)-1].Rip)
		})
	}
}

func TestPtracer_RunShellcode_NotAttached(t *testing.T) {
	p := &ptracer{pid: 1234, sys: &mockSysCalls{}}
	_, err := p.RunShellcode(0x1000, 0x2000)
	assert.Error(t, err)
}

// T19: a short poke must be reported as an error.
func TestPtracer_WriteMem_PartialWrite(t *testing.T) {
	mock := &mockSysCalls{pokeShort: true}
	p := attachedPtracer(mock)
	err := p.WriteMem(0x1000, []byte("hello"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "partial")
}

func TestPtracer_WriteReadMem(t *testing.T) {
	mock := &mockSysCalls{peekData: []byte("abcd")}
	p := attachedPtracer(mock)
	assert.NoError(t, p.WriteMem(0x1000, []byte("hello")))
	assert.Len(t, mock.pokeData, 1)
	buf := make([]byte, 4)
	assert.NoError(t, p.ReadMem(0x1000, buf))
	assert.Equal(t, []byte("abcd"), buf)
}

func TestPtracer_Attach_DoubleAttach(t *testing.T) {
	mock := &mockSysCalls{
		tids:         []int{1234},
		waitStatuses: []unix.WaitStatus{stoppedStatus(unix.SIGSTOP)},
	}
	p := &ptracer{pid: 1234, sys: mock}
	assert.NoError(t, p.Attach())
	err := p.Attach()
	assert.Error(t, err, "double attach must fail (prevents the old double-attach EPERM)")
}

func TestParseExecAddr(t *testing.T) {
	addr, err := parseExecAddr(string(sampleMaps))
	assert.NoError(t, err)
	assert.Equal(t, uintptr(0x555555554000), addr, "must pick the first r-xp region")

	_, err = parseExecAddr("7f0000000000-7f0000001000 rw-p 00000000 00:00 0\n")
	assert.Error(t, err, "no exec mapping")
}

func TestIsSyscallError(t *testing.T) {
	assert.True(t, isSyscallError(negErrno(unix.ENOMEM)))
	assert.False(t, isSyscallError(0x7f00001000))
}

func TestListTIDs_Self(t *testing.T) {
	tids, err := listTIDs(os.Getpid())
	assert.NoError(t, err)
	assert.Contains(t, tids, os.Getpid())
}

func TestErrnoHelpers(t *testing.T) {
	// ensure syscallErrno round-trips the value we encode
	assert.True(t, errors.Is(syscallErrno(negErrno(unix.ENOENT)), unix.ENOENT))
}

// --- T27: OS-thread pinning ---

// Attach must pin the OS thread (ptrace binds a tracee to the thread that attached to
// it) and Detach must release the pin. Go 1.27 removed runtime.LockedOSThread, so the
// pin is asserted through the tracer's own bookkeeping, which is what drives the
// LockOSThread/UnlockOSThread pair.
func TestPtracer_AttachDetach_PinsOSThread(t *testing.T) {
	mock := &mockSysCalls{
		tids:         []int{1234, 1235},
		waitStatuses: []unix.WaitStatus{stoppedStatus(unix.SIGSTOP), stoppedStatus(unix.SIGSTOP)},
	}
	p := &ptracer{pid: 1234, sys: mock, waitTimeout: time.Second}

	assert.False(t, p.osThreadLocked)
	assert.NoError(t, p.Attach())
	assert.True(t, p.osThreadLocked, "Attach must pin the goroutine to one OS thread (T27)")
	assert.NoError(t, p.Detach())
	assert.False(t, p.osThreadLocked, "Detach must release the pin (T27)")
}

// A failed attach must not leave the goroutine pinned to an OS thread.
func TestPtracer_AttachFailure_ReleasesOSThread(t *testing.T) {
	mock := &mockSysCalls{tidsErr: errors.New("cannot read /proc")}
	p := &ptracer{pid: 1234, sys: mock, waitTimeout: time.Second}
	err := p.Attach()
	assert.Error(t, err)
	assert.False(t, p.osThreadLocked, "a failed Attach must unlock the OS thread (T27)")
}

// Detaching twice must not unlock more times than Attach locked.
func TestPtracer_Detach_DoesNotUnlockTwice(t *testing.T) {
	mock := &mockSysCalls{
		tids:         []int{1234},
		waitStatuses: []unix.WaitStatus{stoppedStatus(unix.SIGSTOP)},
	}
	p := &ptracer{pid: 1234, sys: mock, waitTimeout: time.Second}
	assert.NoError(t, p.Attach())
	assert.NoError(t, p.Detach())
	assert.Error(t, p.Detach(), "second Detach must be rejected")
	assert.False(t, p.osThreadLocked)
}

// --- T17: bounded wait ---

// A target that never reports the expected event must produce a timeout instead of an
// unkillable hang in Wait4.
func TestPtracer_Wait_TimesOut(t *testing.T) {
	mock := &mockSysCalls{
		tids:        []int{1234},
		waitNoChild: true,
	}
	p := &ptracer{pid: 1234, sys: mock, waitTimeout: 40 * time.Millisecond}

	start := time.Now()
	err := p.Attach()
	elapsed := time.Since(start)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
	assert.Less(t, elapsed, 5*time.Second, "must give up promptly instead of hanging")
	assert.True(t, mock.waitCalls[0].options&unix.WNOHANG != 0, "bounded wait must use WNOHANG (T17)")
	assert.False(t, p.osThreadLocked, "timed-out attach must release the thread pin")
	assert.NotEmpty(t, mock.detachCalls, "already-stopped LWPs must be released after a timeout")
}

// With no timeout configured the wait stays blocking (options == 0).
func TestPtracer_Wait_BlocksWhenTimeoutDisabled(t *testing.T) {
	mock := &mockSysCalls{
		tids:         []int{1234},
		waitStatuses: []unix.WaitStatus{stoppedStatus(unix.SIGSTOP)},
	}
	p := &ptracer{pid: 1234, sys: mock} // waitTimeout zero => blocking
	assert.NoError(t, p.Attach())
	assert.Equal(t, 0, mock.waitCalls[0].options, "no timeout => blocking Wait4")
	assert.NoError(t, p.Detach())
}

func TestNewTracer_Options(t *testing.T) {
	p := NewTracer(1234, WithWaitTimeout(250*time.Millisecond)).(*ptracer)
	assert.Equal(t, 250*time.Millisecond, p.waitTimeout)
	assert.Equal(t, DefaultWaitTimeout, NewTracer(1234).(*ptracer).waitTimeout)
}

// --- T31: pre-attach diagnostics ---

func TestPtracer_Attach_Precheck(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  string
		wantSub string
	}{
		{"zombie", "Name:\tsleep\nState:\tZ (zombie)\nTgid:\t1234\nTracerPid:\t0\n", "zombie"},
		{"already traced", "Name:\tsleep\nState:\tS (sleeping)\nTgid:\t1234\nTracerPid:\t99\n", "already traced by pid 99"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockSysCalls{status: []byte(tc.status), tids: []int{1234}}
			p := &ptracer{pid: 1234, sys: mock, waitTimeout: DefaultWaitTimeout}
			err := p.Attach()
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantSub)
			assert.Empty(t, mock.attachCalls, "must not attempt PTRACE_ATTACH when the precheck fails")
			assert.False(t, p.osThreadLocked, "a rejected attach must release the thread pin")
		})
	}
}

func TestPtracer_Attach_Precheck_NoSuchProcess(t *testing.T) {
	mock := &mockSysCalls{statusErr: unix.ENOENT}
	p := &ptracer{pid: 4242, sys: mock, waitTimeout: DefaultWaitTimeout}
	err := p.Attach()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist")
	assert.Empty(t, mock.attachCalls)
}

// An unreadable status proves nothing: attach must still be attempted.
func TestPtracer_Attach_Precheck_StatusUnreadableProceeds(t *testing.T) {
	mock := &mockSysCalls{
		statusErr:    unix.EACCES,
		tids:         []int{1234},
		waitStatuses: []unix.WaitStatus{stoppedStatus(unix.SIGSTOP)},
	}
	p := &ptracer{pid: 1234, sys: mock, waitTimeout: DefaultWaitTimeout}
	assert.NoError(t, p.Attach())
	assert.Equal(t, []int{1234}, mock.attachCalls)
	assert.NoError(t, p.Detach())
}

// T31: EPERM on attach must name the Yama scope while keeping the errno matchable.
func TestPtracer_Attach_EPERM_MentionsPtraceScope(t *testing.T) {
	mock := &mockSysCalls{
		tids:      []int{1234},
		attachErr: map[int]error{1234: unix.EPERM},
		status:    []byte("Name:\tsleep\nState:\tS (sleeping)\nTracerPid:\t0\n"),
		scope:     1,
	}
	p := &ptracer{pid: 1234, sys: mock, waitTimeout: DefaultWaitTimeout}
	err := p.Attach()
	assert.ErrorIs(t, err, unix.EPERM, "the original errno must stay wrapped")
	assert.Contains(t, err.Error(), "ptrace_scope is 1")
	assert.False(t, p.osThreadLocked)
}

func TestPtracer_Attach_ESRCH_Explained(t *testing.T) {
	mock := &mockSysCalls{
		tids:      []int{1234},
		attachErr: map[int]error{1234: unix.ESRCH},
	}
	p := &ptracer{pid: 1234, sys: mock, waitTimeout: DefaultWaitTimeout}
	err := p.Attach()
	assert.ErrorIs(t, err, unix.ESRCH)
	assert.Contains(t, err.Error(), "vanished")
}

func TestProcStatusField(t *testing.T) {
	status := []byte("Name:\tsleep\nState:\tS (sleeping)\nTracerPid:\t0\n")
	v, ok := procStatusField(status, "State")
	assert.True(t, ok)
	assert.Equal(t, "S (sleeping)", v)
	v, ok = procStatusField(status, "TracerPid")
	assert.True(t, ok)
	assert.Equal(t, "0", v)
	_, ok = procStatusField(status, "Missing")
	assert.False(t, ok)
}
