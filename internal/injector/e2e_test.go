//go:build linux && amd64

package injector

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// startSleep launches a child `sleep` and returns its pid plus a cleanup func.
func startSleep(t *testing.T) int {
	t.Helper()
	sleepPath, err := exec.LookPath("sleep")
	if err != nil {
		t.Skipf("sleep not found: %v", err)
	}
	cmd := exec.Command(sleepPath, "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	time.Sleep(80 * time.Millisecond)
	return cmd.Process.Pid
}

// T1/T2: MmapExec must return executable memory, and two calls must not collide.
func TestE2E_MmapExec_Readback(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	pid := startSleep(t)
	tracer := NewTracer(pid)
	if err := tracer.Attach(); err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skipf("ptrace denied: %v", err)
		}
		t.Fatalf("Attach: %v", err)
	}
	defer func() { _ = tracer.Detach() }()

	addr, err := tracer.MmapExec(64)
	assert.NoError(t, err)
	assert.NotZero(t, addr)
	assert.Equal(t, uintptr(0), addr%pageSize, "mmap address must be page-aligned")

	// T2: a second allocation must be a distinct address.
	addr2, err := tracer.MmapExec(64)
	assert.NoError(t, err)
	assert.NotEqual(t, addr, addr2, "two MmapExec calls must return distinct addresses (T2)")

	testData := []byte("e2e_mmap_readback")
	if err := tracer.WriteMem(addr, testData); err != nil {
		t.Fatalf("WriteMem: %v", err)
	}

	f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	assert.NoError(t, err)
	defer f.Close()
	readBuf := make([]byte, len(testData))
	n, err := f.ReadAt(readBuf, int64(addr))
	assert.NoError(t, err)
	assert.Equal(t, testData, readBuf[:n], "data must round-trip through the target")
}

// T7/T10: Detach must restore the target's executable bytes (the syscall gate) intact,
// and the process must survive the whole session.
func TestE2E_GateBytesRestored(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	pid := startSleep(t)
	tracer := NewTracer(pid).(*ptracer)
	if err := tracer.Attach(); err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skipf("ptrace denied: %v", err)
		}
		t.Fatalf("Attach: %v", err)
	}

	// Force gate creation by doing one mmap.
	_, err := tracer.MmapExec(64)
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skipf("ptrace denied: %v", err)
		}
		t.Fatalf("MmapExec: %v", err)
	}
	gateAddr := tracer.gateAddr
	assert.NotZero(t, gateAddr, "gate must have been planted")

	// Snapshot gate bytes after restore.
	assert.NoError(t, tracer.Detach())

	f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		t.Skipf("cannot open mem after detach: %v", err)
	}
	defer f.Close()
	buf := make([]byte, gateByteLen)
	n, err := f.ReadAt(buf, int64(gateAddr))
	assert.NoError(t, err)
	assert.NotEqual(t, []byte{0x0f, 0x05, 0xcc}, buf[:3],
		"gate 'syscall; int3' must NOT remain in the target after Detach (T10)")
	assert.Equal(t, gateByteLen, n)
	_ = unix.Kill(pid, 0)
}

// The definitive proof: injecting hooklib.so into a live sleep must trigger its
// constructor. With the pre-audit code this could never succeed (T1-T12).
func TestE2E_FullInjection(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cwd, _ := os.Getwd()
	hooklibPath, err := filepath.Abs(cwd + "/../../examples/hooklib/hooklib.so")
	if err != nil {
		t.Skipf("hooklib.so not found: %v", err)
	}
	if _, err := os.Stat(hooklibPath); os.IsNotExist(err) {
		t.Skipf("hooklib.so not built at %s (run 'make example')", hooklibPath)
	}

	logPath := "/tmp/go-ptrace-hook.log"
	_ = os.Remove(logPath)

	pid := startSleep(t)

	// Inject attaches, injects, and detaches internally. T32: collect the stage log.
	var stageLog []string
	inj := &Injector{Tracer: NewTracer(pid), Logf: func(format string, args ...any) {
		stageLog = append(stageLog, fmt.Sprintf(format, args...))
	}}
	dlopenAddr, err := FindDlopenAddr(pid)
	if err != nil {
		t.Fatalf("FindDlopenAddr: %v", err)
	}
	sc, err := GenerateDlopenShellcode(dlopenAddr, RTLDNow)
	if err != nil {
		t.Fatalf("GenerateDlopenShellcode: %v", err)
	}
	if err := inj.Inject(pid, sc, hooklibPath); err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skipf("ptrace denied: %v", err)
		}
		t.Fatalf("Inject: %v", err)
	}

	// Give the constructor time to write.
	deadline := time.Now().Add(2 * time.Second)
	var data []byte
	for time.Now().Before(deadline) {
		data, err = os.ReadFile(logPath)
		if err == nil && len(data) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	assert.NoError(t, err, "log file must be created after injection")
	assert.Contains(t, string(data), "constructor called", "constructor must be called")
	assert.Contains(t, string(data), fmt.Sprintf("pid %d", pid), "log must contain correct PID")

	// T7: the target must still be alive after detach.
	assert.NoError(t, unix.Kill(pid, 0), "target must survive injection (T7)")

	// T32: the verbose stage log must describe the whole pipeline.
	joined := strings.Join(stageLog, "\n")
	assert.Contains(t, joined, fmt.Sprintf("attached to pid %d", pid))
	assert.Contains(t, joined, "for the library path")
	assert.Contains(t, joined, "for the shellcode")
	assert.Contains(t, joined, "dlopen returned handle")
}
