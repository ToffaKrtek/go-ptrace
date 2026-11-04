package injector

import (
	"errors"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

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
