package injector

import (
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFindDlopenAddr_Success(t *testing.T) {
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

	// Give the process time to load libraries
	time.Sleep(100 * time.Millisecond)

	addr, err := FindDlopenAddr(cmd.Process.Pid)
	assert.NoError(t, err, "FindDlopenAddr must succeed for a real process")
	assert.NotZero(t, addr, "dlopen address must not be zero")
}

func TestFindDlopenAddr_InvalidPID(t *testing.T) {
	_, err := FindDlopenAddr(999999)
	assert.Error(t, err, "FindDlopenAddr must fail for invalid PID")
}
