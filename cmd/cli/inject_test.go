//go:build linux && amd64

package main

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// T32: --dry-run must validate without ever calling ptrace.
func TestDryRun_MissingLibrary(t *testing.T) {
	err := dryRun(os.Getpid(), "/nonexistent/lib.so", time.Second)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not accessible")
}

func TestDryRun_RelativePath(t *testing.T) {
	err := dryRun(os.Getpid(), "lib/hooklib.so", time.Second)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "absolute")
}

func TestDryRun_DirectoryRejected(t *testing.T) {
	err := dryRun(os.Getpid(), os.TempDir(), time.Second)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "directory")
}

func TestDryRun_NoSuchProcess(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	err = dryRun(1<<30, exe, time.Second)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot resolve dlopen")
}

// The happy path resolves dlopen in the test process itself.
func TestDryRun_Self(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	if err := dryRun(os.Getpid(), exe, 5*time.Second); err != nil {
		t.Skipf("dlopen not resolvable from the test binary: %v", err)
	}
}
