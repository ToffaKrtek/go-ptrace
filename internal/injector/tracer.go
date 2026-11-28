//go:build linux && amd64

package injector

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	pageSize = 4096
	wordSize = 8

	// syscallGate is "syscall; int3; nop*5" (8 bytes). int3 traps back to the tracer
	// right after the syscall retires, so RAX can be read and state restored.
	gateByteLen = 8
)

// sysCalls is the low-level seam the ptracer depends on. Everything that touches the
// kernel or /proc goes through it, so the ptracer can be unit-tested against a mock.
type sysCalls interface {
	PtraceAttach(pid int) error
	PtraceDetach(pid int) error
	PtracePeekData(pid int, addr uintptr, out []byte) (int, error)
	PtracePeekText(pid int, addr uintptr, out []byte) (int, error)
	PtracePokeData(pid int, addr uintptr, data []byte) (int, error)
	PtracePokeText(pid int, addr uintptr, data []byte) (int, error)
	PtraceGetRegs(pid int, regs *unix.PtraceRegs) error
	PtraceSetRegs(pid int, regs *unix.PtraceRegs) error
	PtraceCont(pid int, sig int) error
	PtraceSetOptions(pid int, options int) error
	Wait4(pid int, status *unix.WaitStatus, options int, rusage *unix.Rusage) (int, error)
	ListTIDs(pid int) ([]int, error)
	ReadMaps(pid int) ([]byte, error)
	// ReadStatus returns the contents of /proc/<pid>/status.
	ReadStatus(pid int) ([]byte, error)
	// ReadPtraceScope returns /proc/sys/kernel/yama/ptrace_scope (-1 when unavailable).
	ReadPtraceScope() (int, error)
}

// Tracer is the primitive interface the Injector orchestrates against. It reflects real
// ptrace semantics (T33): attach stops every LWP, memory is written/read directly, and
// remote execution goes through explicit syscall / shellcode entrypoints that restore
// the target's state.
type Tracer interface {
	Attach() error
	Detach() error
	MmapExec(size int) (uintptr, error)
	WriteMem(addr uintptr, data []byte) error
	ReadMem(addr uintptr, data []byte) error
	RunShellcode(addr uintptr, arg uintptr) (uint64, error)
}

type ptracer struct {
	pid            int
	sys            sysCalls
	waitTimeout    time.Duration
	tids           []int
	savedRegs      *unix.PtraceRegs
	attached       bool
	osThreadLocked bool
	gateAddr       uintptr
	gateBackup     []byte
}

// DefaultWaitTimeout bounds how long the tracer waits for a wait4 event before giving up
// (T17). A hijacked target that never traps (e.g. shellcode that loops) would otherwise
// hang the tracer forever inside a blocking Wait4.
const DefaultWaitTimeout = 30 * time.Second

// TracerOption configures a Tracer created by NewTracer.
type TracerOption func(*ptracer)

// WithWaitTimeout overrides how long a single wait for a ptrace event may take.
// A non-positive value restores the unbounded (blocking) behaviour.
func WithWaitTimeout(d time.Duration) TracerOption {
	return func(p *ptracer) { p.waitTimeout = d }
}

// NewTracer creates a Tracer bound to the given PID.
func NewTracer(pid int, opts ...TracerOption) Tracer {
	p := &ptracer{pid: pid, sys: &unixSysCalls{}, waitTimeout: DefaultWaitTimeout}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Attach stops every LWP of the target (T13), waits for each to report a group-stop
// (T8/T9), enables PTRACE_O_EXITKILL so the target is killed if we die (T15), and
// snapshots the leader's registers for later restoration.
//
// T27: ptrace is thread-bound — a tracee is attached to the OS thread that called
// PTRACE_ATTACH, and PTRACE_SETOPTIONS / SETREGS / CONT on it are only valid from that
// same thread. LockOSThread pins the calling goroutine to one OS thread for the whole
// session; Detach releases it. Attach and Detach must therefore run on the same
// goroutine — Injector always defers Detach immediately after Attach.
func (p *ptracer) Attach() error {
	if p.attached {
		return errors.New("already attached")
	}
	runtime.LockOSThread()
	p.osThreadLocked = true

	if err := p.attachAll(); err != nil {
		p.unlockOSThread()
		return err
	}
	return nil
}

func (p *ptracer) attachAll() error {
	if err := p.precheck(); err != nil {
		return err
	}
	tids, err := p.sys.ListTIDs(p.pid)
	if err != nil {
		return fmt.Errorf("list tids: %w", err)
	}
	if len(tids) == 0 {
		return fmt.Errorf("no threads found for pid %d", p.pid)
	}

	var stopErr error
	for _, tid := range tids {
		if err := p.sys.PtraceAttach(tid); err != nil {
			stopErr = fmt.Errorf("attach tid %d: %w", tid, p.annotateAttachError(tid, err))
			break
		}
		if err := p.waitStop(tid); err != nil {
			stopErr = fmt.Errorf("wait stop tid %d: %w", tid, err)
			break
		}
	}
	p.tids = tids

	if stopErr != nil {
		p.detachAll()
		return stopErr
	}

	// EXITKILL is best-effort per tracee; a failure here is not fatal to correctness.
	for _, tid := range tids {
		_ = p.sys.PtraceSetOptions(tid, unix.PTRACE_O_EXITKILL)
	}

	var regs unix.PtraceRegs
	if err := p.sys.PtraceGetRegs(p.pid, &regs); err != nil {
		p.detachAll()
		return fmt.Errorf("get regs: %w", err)
	}
	p.savedRegs = &regs
	p.attached = true
	return nil
}

// unlockOSThread releases the OS-thread pin taken by Attach, at most once.
func (p *ptracer) unlockOSThread() {
	if p.osThreadLocked {
		runtime.UnlockOSThread()
		p.osThreadLocked = false
	}
}

// Detach restores the syscall gate bytes and the leader's registers, then releases all
// LWPs. It is safe to call after a partial failure (T14) and must run on the same
// goroutine as Attach so the thread pin (T27) is released on the right thread.
func (p *ptracer) Detach() error {
	if !p.attached {
		return errors.New("not attached")
	}
	p.rollback()
	err := p.detachAll()
	p.unlockOSThread()
	return err
}

func (p *ptracer) detachAll() error {
	var firstErr error
	for _, tid := range p.tids {
		if err := p.sys.PtraceDetach(tid); err != nil && !errors.Is(err, unix.ESRCH) {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	p.tids = nil
	p.attached = false
	return firstErr
}

// precheck runs cheap diagnostics before PTRACE_ATTACH (T31) so that the usual failure
// modes stop with an actionable reason instead of a bare EPERM/ESRCH: the process is
// gone, it is a zombie, or another tracer already owns it.
func (p *ptracer) precheck() error {
	data, err := p.sys.ReadStatus(p.pid)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("process %d does not exist", p.pid)
		}
		// An unreadable status proves nothing about traceability, so let the attach
		// itself decide rather than rejecting a possibly valid target.
		return nil
	}
	if state, ok := procStatusField(data, "State"); ok && strings.HasPrefix(state, "Z") {
		return fmt.Errorf("process %d is a zombie (%s); a defunct process cannot be injected", p.pid, state)
	}
	if field, ok := procStatusField(data, "TracerPid"); ok {
		if tracer, convErr := strconv.Atoi(field); convErr == nil && tracer > 0 {
			return fmt.Errorf("process %d is already traced by pid %d; stop the other debugger first", p.pid, tracer)
		}
	}
	return nil
}

// annotateAttachError explains a raw PTRACE_ATTACH failure (T31). The original errno is
// always wrapped, so callers can still match it with errors.Is.
func (p *ptracer) annotateAttachError(tid int, err error) error {
	switch {
	case errors.Is(err, unix.EPERM):
		scope, scopeErr := p.sys.ReadPtraceScope()
		if scopeErr == nil && scope > 0 {
			return fmt.Errorf("%w: kernel.yama.ptrace_scope is %d, which only lets a parent trace its direct children; run as root or set it to 0", err, scope)
		}
		return fmt.Errorf("%w: permission denied; need CAP_SYS_PTRACE or to be the owner of tid %d", err, tid)
	case errors.Is(err, unix.ESRCH):
		return fmt.Errorf("%w: tid %d vanished before it could be stopped", err, tid)
	default:
		return err
	}
}

// procStatusField returns the trimmed value of a "Key:\tvalue" line in /proc/<pid>/status.
func procStatusField(status []byte, key string) (string, bool) {
	prefix := key + ":"
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(line[len(prefix):]), true
		}
	}
	return "", false
}

// rollback undoes any in-progress hijack: restores the gate bytes and the saved registers.
func (p *ptracer) rollback() {
	if p.gateAddr != 0 && p.gateBackup != nil {
		_, _ = p.sys.PtracePokeText(p.pid, p.gateAddr, p.gateBackup)
		p.gateAddr = 0
		p.gateBackup = nil
	}
	if p.savedRegs != nil {
		_ = p.sys.PtraceSetRegs(p.pid, p.savedRegs)
	}
}

// MmapExec allocates readable+writeable+executable anonymous memory inside the target
// via a remote mmap syscall (T1/T2/T20). Each call returns a fresh region, so the path
// string and the shellcode never share an address (T2). T21: failure is reported through
// error, not a MAP_FAILED sentinel.
func (p *ptracer) MmapExec(size int) (uintptr, error) {
	if !p.attached {
		return 0, errors.New("not attached")
	}
	if size <= 0 {
		return 0, errors.New("invalid mmap size: must be positive")
	}
	aligned := uint64((size + pageSize - 1) &^ (pageSize - 1))

	ret, err := p.remoteSyscall(unix.SYS_MMAP, [6]uint64{
		0, // addr: let the kernel choose
		aligned,
		unix.PROT_READ | unix.PROT_WRITE | unix.PROT_EXEC,
		unix.MAP_PRIVATE | unix.MAP_ANONYMOUS,
		^uint64(0), // fd = -1
		0,          // offset
	})
	if err != nil {
		return 0, err
	}
	if isSyscallError(ret) {
		return 0, fmt.Errorf("remote mmap failed: %w", syscallErrno(ret))
	}
	if ret == 0 {
		return 0, errors.New("remote mmap returned NULL")
	}
	return uintptr(ret), nil
}

// WriteMem writes data into the target's memory (T19: a short write is an error).
func (p *ptracer) WriteMem(addr uintptr, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	n, err := p.sys.PtracePokeData(p.pid, addr, data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return fmt.Errorf("partial poke: wrote %d of %d bytes at 0x%x", n, len(data), addr)
	}
	return nil
}

// ReadMem reads data from the target's memory.
func (p *ptracer) ReadMem(addr uintptr, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	n, err := p.sys.PtracePeekData(p.pid, addr, data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return fmt.Errorf("partial peek: read %d of %d bytes at 0x%x", n, len(data), addr)
	}
	return nil
}

// RunShellcode hijacks the leader's RIP to the given executable address, passes arg in
// RDI, runs until the shellcode's int3 traps, captures RAX, and restores the registers.
// The caller must have already written the shellcode (with a trailing int3) at addr.
func (p *ptracer) RunShellcode(addr uintptr, arg uintptr) (uint64, error) {
	if !p.attached {
		return 0, errors.New("not attached")
	}
	var regs unix.PtraceRegs
	if err := p.sys.PtraceGetRegs(p.pid, &regs); err != nil {
		return 0, fmt.Errorf("get regs: %w", err)
	}
	orig := regs

	regs.Rip = uint64(addr)
	regs.Rdi = uint64(arg)
	// Clear the in-flight syscall state before hijacking. The target is typically
	// stopped inside a restartable syscall (e.g. clock_nanosleep) with
	// RAX = -ERESTART_RESTARTBLOCK and ORIG_RAX = <syscall nr>. On the next return
	// to user space the kernel's syscall-restart path would run
	// `regs->ax = NR_restart_syscall; regs->ip -= 2` (arch/x86/kernel/signal.c),
	// overwriting our hijack: execution would start at addr-2 (unmapped) and the
	// target would die with SIGSEGV. ORIG_RAX = -1 makes syscall_get_nr() report
	// "not in a syscall", disabling the restart entirely.
	regs.Orig_rax = ^uint64(0)
	if err := p.sys.PtraceSetRegs(p.pid, &regs); err != nil {
		return 0, fmt.Errorf("set regs: %w", err)
	}

	if err := p.sys.PtraceCont(p.pid, 0); err != nil {
		_ = p.sys.PtraceSetRegs(p.pid, &orig)
		return 0, fmt.Errorf("cont: %w", err)
	}
	if err := p.waitTrap(); err != nil {
		_ = p.sys.PtraceSetRegs(p.pid, &orig)
		return 0, err
	}

	var res unix.PtraceRegs
	if err := p.sys.PtraceGetRegs(p.pid, &res); err != nil {
		_ = p.sys.PtraceSetRegs(p.pid, &orig)
		return 0, fmt.Errorf("get regs after: %w", err)
	}
	if err := p.sys.PtraceSetRegs(p.pid, &orig); err != nil {
		return 0, fmt.Errorf("restore regs: %w", err)
	}
	return res.Rax, nil
}

// remoteSyscall sets up a syscall in the target via a temporary "syscall; int3" gate
// placed in an existing executable mapping, runs it, reads RAX, and restores everything.
func (p *ptracer) remoteSyscall(num uintptr, args [6]uint64) (uint64, error) {
	if err := p.ensureGate(); err != nil {
		return 0, err
	}

	var regs unix.PtraceRegs
	if err := p.sys.PtraceGetRegs(p.pid, &regs); err != nil {
		return 0, fmt.Errorf("get regs: %w", err)
	}
	orig := regs

	regs.Rip = uint64(p.gateAddr)
	regs.Rax = uint64(num)
	// Same syscall-restart guard as in RunShellcode: a stale ORIG_RAX from an
	// interrupted syscall would let the kernel rewind RIP by 2 on resume.
	regs.Orig_rax = ^uint64(0)
	regs.Rdi = args[0]
	regs.Rsi = args[1]
	regs.Rdx = args[2]
	regs.R10 = args[3]
	regs.R8 = args[4]
	regs.R9 = args[5]
	if err := p.sys.PtraceSetRegs(p.pid, &regs); err != nil {
		return 0, fmt.Errorf("set regs: %w", err)
	}

	if err := p.sys.PtraceCont(p.pid, 0); err != nil {
		_ = p.sys.PtraceSetRegs(p.pid, &orig)
		return 0, fmt.Errorf("cont: %w", err)
	}
	if err := p.waitTrap(); err != nil {
		_ = p.sys.PtraceSetRegs(p.pid, &orig)
		return 0, err
	}

	var res unix.PtraceRegs
	if err := p.sys.PtraceGetRegs(p.pid, &res); err != nil {
		_ = p.sys.PtraceSetRegs(p.pid, &orig)
		return 0, fmt.Errorf("get regs after: %w", err)
	}
	if err := p.sys.PtraceSetRegs(p.pid, &orig); err != nil {
		return 0, fmt.Errorf("restore regs: %w", err)
	}
	return res.Rax, nil
}

// ensureGate locates an executable mapping in the target and plants a "syscall; int3"
// gate there, backing up the original bytes (T10) so they can be restored on Detach.
func (p *ptracer) ensureGate() error {
	if p.gateAddr != 0 {
		return nil
	}
	addr, err := p.findExecAddr()
	if err != nil {
		return err
	}
	backup := make([]byte, gateByteLen)
	n, err := p.sys.PtracePeekText(p.pid, addr, backup)
	if err != nil {
		return fmt.Errorf("peek gate bytes: %w", err)
	}
	if n != gateByteLen {
		return fmt.Errorf("partial peek of gate bytes: %d", n)
	}
	gate := []byte{0x0f, 0x05, 0xcc, 0x90, 0x90, 0x90, 0x90, 0x90}
	if _, err := p.sys.PtracePokeText(p.pid, addr, gate); err != nil {
		return fmt.Errorf("poke gate: %w", err)
	}
	p.gateAddr = addr
	p.gateBackup = backup
	return nil
}

// findExecAddr returns a page-aligned start of an r-xp mapping in the target, used as the
// syscall gate location. All LWPs are stopped, so temporarily overwriting executable code
// is safe.
func (p *ptracer) findExecAddr() (uintptr, error) {
	data, err := p.sys.ReadMaps(p.pid)
	if err != nil {
		return 0, fmt.Errorf("read maps: %w", err)
	}
	return parseExecAddr(string(data))
}

// parseExecAddr scans maps content for the first r-xp region big enough for the gate.
func parseExecAddr(mapsData string) (uintptr, error) {
	for _, line := range strings.Split(mapsData, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[1] != "r-xp" {
			continue
		}
		var start, end uintptr
		if _, err := fmt.Sscanf(fields[0], "%x-%x", &start, &end); err != nil {
			continue
		}
		if end-start < gateByteLen {
			continue
		}
		return start, nil
	}
	return 0, errors.New("no executable (r-xp) mapping found in target")
}

// waitStop waits for a thread to enter a group-stop (SIGSTOP after ATTACH, T9).
func (p *ptracer) waitStop(tid int) error {
	return p.wait(func(status unix.WaitStatus) error {
		if status.Stopped() {
			return nil
		}
		return statusError(status)
	})
}

// waitTrap waits for the leader to trap on int3 (SIGTRAP), distinguishing an unexpected
// exit or fatal signal from a genuine trap (T18).
func (p *ptracer) waitTrap() error {
	return p.wait(func(status unix.WaitStatus) error {
		if status.Stopped() && status.StopSignal() == unix.SIGTRAP {
			return nil
		}
		return statusError(status)
	})
}

// Polling bounds for the non-blocking wait loop (T17).
const (
	waitPollMinInterval = 20 * time.Microsecond
	waitPollMaxInterval = 2 * time.Millisecond
)

// wait polls Wait4 for the leader/tid until cond is satisfied, EINTR retries are
// exhausted, or the configured wait timeout expires (T17). WNOHANG is used on purpose: a
// target that never reports the expected event (shellcode that loops instead of hitting
// the trailing int3, a wedged remote syscall) then yields a timeout error rather than
// hanging the tracer forever in an uninterruptible blocking wait. A waitTimeout <= 0
// restores the classic blocking behaviour.
func (p *ptracer) wait(cond func(unix.WaitStatus) error) error {
	var status unix.WaitStatus
	var deadline time.Time
	timed := p.waitTimeout > 0
	if timed {
		deadline = time.Now().Add(p.waitTimeout)
	}
	interval := waitPollMinInterval

	timedOut := func() bool {
		return timed && !time.Now().Before(deadline)
	}

	for {
		options := 0
		if timed {
			options = unix.WNOHANG
		}
		pid, err := p.sys.Wait4(p.pid, &status, options, nil)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				if timedOut() {
					return p.waitTimeoutError()
				}
				continue
			}
			return err
		}
		if pid == 0 {
			// WNOHANG: nothing changed state yet.
			if timedOut() {
				return p.waitTimeoutError()
			}
			time.Sleep(interval)
			if interval < waitPollMaxInterval {
				interval *= 2
				if interval > waitPollMaxInterval {
					interval = waitPollMaxInterval
				}
			}
			continue
		}
		return cond(status)
	}
}

func (p *ptracer) waitTimeoutError() error {
	return fmt.Errorf("timeout after %s waiting for pid %d to report a ptrace event; the target may be wedged inside the injected code", p.waitTimeout, p.pid)
}

func statusError(status unix.WaitStatus) error {
	switch {
	case status.Exited():
		return fmt.Errorf("target exited with status %d", status.ExitStatus())
	case status.Signaled():
		return fmt.Errorf("target terminated by signal %v", status.Signal())
	case status.Stopped():
		return fmt.Errorf("unexpected stop signal %v", status.StopSignal())
	default:
		return errors.New("target in unexpected wait state")
	}
}

// isSyscallError reports whether a raw syscall return encodes -errno (values in the
// last 4095 of the address space).
func isSyscallError(ret uint64) bool {
	return ret >= ^uint64(4095) // 0xFFFFFFFFFFFFF000 == (uint64)(-4096)
}

func syscallErrno(ret uint64) error {
	return unix.Errno(-int64(ret))
}

// listTIDs reads /proc/<pid>/task and returns the numeric thread ids in ascending order.
func listTIDs(pid int) ([]int, error) {
	dir := filepath.Join("/proc", strconv.Itoa(pid), "task")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	tids := make([]int, 0, len(entries))
	for _, e := range entries {
		tid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		tids = append(tids, tid)
	}
	sort.Ints(tids)
	return tids, nil
}
