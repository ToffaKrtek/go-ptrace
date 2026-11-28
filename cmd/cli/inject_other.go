//go:build !linux || !amd64

package main

import (
	"errors"
	"time"
)

// ptrace injection is implemented for linux/amd64 only: the shellcode, the register
// layout and the syscall gate are all x86_64 specific. The CLI still builds elsewhere so
// that --help and argument validation keep working; the actual work refuses.
func inject(pid int, libPath string, opts injectOptions) error {
	return errors.New("ptrace injection is only supported on linux/amd64")
}

func dryRun(pid int, libPath string, timeout time.Duration) error {
	return errors.New("dry run is only supported on linux/amd64")
}
