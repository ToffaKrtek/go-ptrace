//go:build linux && amd64

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/ToffaKrtek/go-ptrace/internal/injector"
)

func inject(pid int, libPath string, opts injectOptions) error {
	tracer := injector.NewTracer(pid, injector.WithWaitTimeout(opts.Timeout))
	inj := injector.NewInjector(tracer)
	if opts.Verbose {
		logger := log.New(os.Stderr, "", 0)
		inj.Logf = logger.Printf
	}
	return inj.InjectLibrary(pid, libPath)
}

// dryRun reports what the injection would do, using only read-only inspection (T32):
// the library file, the target's memory map and the resolved dlopen address. It never
// calls ptrace, so it is safe against processes the user may not even ptrace.
func dryRun(pid int, libPath string, timeout time.Duration) error {
	if !filepath.IsAbs(libPath) {
		return fmt.Errorf("library path must be absolute (it is resolved in the target's namespace): %q", libPath)
	}
	info, err := os.Stat(libPath)
	if err != nil {
		return fmt.Errorf("library not accessible: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("library path is a directory: %s", libPath)
	}

	dlopenAddr, err := injector.FindDlopenAddr(pid)
	if err != nil {
		return fmt.Errorf("cannot resolve dlopen in pid %d: %w", pid, err)
	}
	shellcode, err := injector.GenerateDlopenShellcode(dlopenAddr, injector.RTLDNow)
	if err != nil {
		return err
	}

	fmt.Printf("dry run for pid %d (no ptrace calls made)\n", pid)
	fmt.Printf("  library    : %s (%d bytes)\n", libPath, info.Size())
	fmt.Printf("  dlopen     : 0x%x\n", dlopenAddr)
	fmt.Printf("  shellcode  : %d bytes at an anonymous rwxp mapping\n", len(shellcode))
	fmt.Printf("  payload    : %d bytes (path + NUL)\n", len(libPath)+1)
	fmt.Printf("  flags      : RTLD_NOW (0x%x), wait timeout %s\n", injector.RTLDNow, timeout)
	return nil
}
