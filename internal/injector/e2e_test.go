package injector

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestE2E_FullInjection(t *testing.T) {
	t.Parallel()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Find hooklib.so (go up two dirs from internal/injector to project root)
	cwd, _ := os.Getwd()
	hooklibPath := cwd + "/../../examples/hooklib/hooklib.so"
	if _, err := os.Stat(hooklibPath); os.IsNotExist(err) {
		t.Skipf("hooklib.so not found at %s", hooklibPath)
	}

	sleepPath, err := exec.LookPath("sleep")
	if err != nil {
		t.Skipf("sleep not found: %v", err)
	}

	// Clean up log file
	logPath := "/tmp/go-ptrace-hook.log"
	_ = os.Remove(logPath)

	cmd := exec.Command(sleepPath, "30")
	err = cmd.Start()
	assert.NoError(t, err)
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	// Give the process time to load
	time.Sleep(100 * time.Millisecond)

	tracer := NewTracer(cmd.Process.Pid)
	err = tracer.Attach()
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skipf("ptrace denied: %v", err)
		}
		t.Fatalf("Attach: %v", err)
	}
	t.Cleanup(func() { _ = tracer.Detach() })

	_, err = unix.Wait4(cmd.Process.Pid, nil, 0, nil)
	assert.NoError(t, err)

	// Inject the library
	inj := &Injector{Tracer: tracer}
	err = inj.InjectLibrary(cmd.Process.Pid, hooklibPath)
	if err != nil {
		if errors.Is(err, unix.EPERM) || (err != nil && err.Error() == "attach to process: operation not permitted") {
			t.Skipf("ptrace denied: %v", err)
		}
		t.Fatalf("InjectLibrary: %v", err)
	}
	assert.NoError(t, err, "InjectLibrary must succeed")

	// The process should have stopped on SIGTRAP (from int3 in shellcode)
	// Check that the log file was created (constructor was called)
	time.Sleep(100 * time.Millisecond)
	data, err := os.ReadFile(logPath)
	assert.NoError(t, err, "log file must be created after injection")
	assert.Contains(t, string(data), "constructor called", "constructor must be called")
	assert.Contains(t, string(data), fmt.Sprintf("pid %d", cmd.Process.Pid), "log must contain correct PID")
}

func TestE2E_Mmap_PokeData_Readback(t *testing.T) {
	t.Parallel()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	sleepPath, err := exec.LookPath("sleep")
	if err != nil {
		t.Skipf("sleep not found: %v", err)
	}
	cmd := exec.Command(sleepPath, "30")
	err = cmd.Start()
	assert.NoError(t, err)
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	tracer := NewTracer(cmd.Process.Pid)
	err = tracer.Attach()
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skipf("ptrace denied: %v", err)
		}
		t.Fatalf("Attach: %v", err)
	}
	t.Cleanup(func() { _ = tracer.Detach() })

	_, err = unix.Wait4(cmd.Process.Pid, nil, 0, nil)
	assert.NoError(t, err)

	// Allocate memory via Mmap
	addr, err := tracer.Mmap(64)
	assert.NoError(t, err)
	assert.NotZero(t, addr)

	// Write data via PokeData
	testData := []byte("e2e_mmap_test_data")
	err = tracer.PokeData(addr, testData)
	assert.NoError(t, err, "PokeData to Mmap address must succeed")

	// Read back via /proc/pid/mem
	f, err := os.Open(fmt.Sprintf("/proc/%d/mem", cmd.Process.Pid))
	assert.NoError(t, err)
	defer f.Close()

	readBuf := make([]byte, len(testData))
	n, err := f.ReadAt(readBuf, int64(addr))
	assert.NoError(t, err)
	assert.Equal(t, len(testData), n)
	assert.Equal(t, testData, readBuf[:n], "data must match after Mmap+PokeData")
}

func TestE2E_TracerAttachDetachOwnedSleep(t *testing.T) {
	t.Run("attach wait-stop detach own child process", func(t *testing.T) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		sleepPath, err := exec.LookPath("sleep")
		if err != nil {
			t.Skipf("sleep not found: %v", err)
		}
		cmd := exec.Command(sleepPath, "30")
		err = cmd.Start()
		assert.NoError(t, err)
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		})
		pid := cmd.Process.Pid
		timer := time.AfterFunc(5*time.Second, func() {
			_ = cmd.Process.Kill()
		})
		defer timer.Stop()
		tracer := NewTracer(pid)
		attached := false
		t.Cleanup(func() {
			if attached {
				_ = tracer.Detach()
			}
		})
		err = tracer.Attach()
		if err != nil {
			if errors.Is(err, unix.EPERM) {
				t.Skipf("ptrace denied by kernel policy: %v", err)
			}
			t.Fatalf("Attach(%d): %v", pid, err)
		}
		attached = true
		var status unix.WaitStatus
		var waitedPID int

		for {
			waitedPID, err = unix.Wait4(pid, &status, 0, nil)
			if !errors.Is(err, unix.EINTR) {
				break
			}
		}
		assert.NoError(t, err)
		assert.Equal(t, pid, waitedPID)
		assert.True(t, status.Stopped())
		sig := status.StopSignal()
		assert.True(t, sig == unix.SIGSTOP || sig == unix.SIGTRAP)
		err = tracer.Detach()
		assert.NoError(t, err)
		attached = false
		err = unix.Kill(pid, 0)
		assert.NoError(t, err)
	})
}
