//go:build linux && amd64

package injector

import (
	"errors"
	"fmt"
	"path/filepath"
)

// RTLDNow is the dlopen flag used by InjectLibrary: resolve all symbols eagerly so a
// broken dependency fails the injection instead of surfacing later inside the target.
const RTLDNow = 0x2

// Injector orchestrates a ptrace-based library injection over a Tracer.
type Injector struct {
	Tracer Tracer
	// Logf, when set, receives a progress line for every pipeline stage (T32). It is
	// nil by default, which keeps the library silent.
	Logf func(format string, args ...any)
}

// NewInjector creates a new Injector with the given Tracer.
func NewInjector(t Tracer) *Injector {
	return &Injector{Tracer: t}
}

func (inj *Injector) logf(format string, args ...any) {
	if inj.Logf != nil {
		inj.Logf(format, args...)
	}
}

// InjectLibrary injects a shared library into a target process by PID. It attaches
// first, then resolves dlopen while the target's memory map is stable (T23), generates
// the shellcode, and runs the injection.
func (inj *Injector) InjectLibrary(pid int, libPath string) error {
	if err := validateLibPath(libPath); err != nil {
		return err
	}

	t := inj.Tracer
	if err := t.Attach(); err != nil {
		return fmt.Errorf("attach to process: %w", err)
	}
	// Detach always runs and rolls back the gate bytes + registers (T14).
	defer func() { _ = t.Detach() }()
	inj.logf("attached to pid %d", pid)

	dlopenAddr, err := FindDlopenAddr(pid)
	if err != nil {
		return fmt.Errorf("find dlopen: %w", err)
	}
	inj.logf("resolved dlopen at 0x%x", dlopenAddr)

	shellcode, err := GenerateDlopenShellcode(dlopenAddr, RTLDNow)
	if err != nil {
		return fmt.Errorf("generate shellcode: %w", err)
	}
	inj.logf("generated %d bytes of dlopen shellcode", len(shellcode))
	return inj.runInjection(t, shellcode, libPath)
}

// Inject injects a pre-generated shellcode (e.g. via GenerateDlopenShellcode) that loads
// libPath. The shellcode is expected to take the path in RDI and end with int3.
func (inj *Injector) Inject(pid int, shellcode []byte, libPath string) error {
	if err := validateLibPath(libPath); err != nil {
		return err
	}
	if len(shellcode) == 0 {
		return errors.New("shellcode must not be empty")
	}

	t := inj.Tracer
	if err := t.Attach(); err != nil {
		return fmt.Errorf("attach to process: %w", err)
	}
	defer func() { _ = t.Detach() }()
	inj.logf("attached to pid %d", pid)

	return inj.runInjection(t, shellcode, libPath)
}

// runInjection performs the allocation, memory writes, and hijack. It assumes the target
// is already attached and will be detached by the caller.
func (inj *Injector) runInjection(t Tracer, shellcode []byte, libPath string) error {
	payload := append([]byte(libPath), 0)

	strAddr, err := t.MmapExec(len(payload))
	if err != nil {
		return fmt.Errorf("mmap for lib path: %w", err)
	}
	inj.logf("allocated 0x%x in the target for the library path (%d bytes)", strAddr, len(payload))

	codeAddr, err := t.MmapExec(len(shellcode))
	if err != nil {
		return fmt.Errorf("mmap for shellcode: %w", err)
	}
	inj.logf("allocated 0x%x in the target for the shellcode (%d bytes)", codeAddr, len(shellcode))

	// T2: the two allocations must be distinct or the shellcode would overwrite the path.
	if strAddr == codeAddr {
		return errors.New("path and shellcode share an address; remote allocation is broken")
	}

	if err := t.WriteMem(strAddr, payload); err != nil {
		return fmt.Errorf("write lib path: %w", err)
	}
	if err := t.WriteMem(codeAddr, shellcode); err != nil {
		return fmt.Errorf("write shellcode: %w", err)
	}
	inj.logf("wrote path and shellcode, hijacking RIP to 0x%x with RDI=0x%x", codeAddr, strAddr)

	handle, err := t.RunShellcode(codeAddr, strAddr)
	if err != nil {
		return fmt.Errorf("run shellcode: %w", err)
	}
	// T12: a NULL handle means dlopen failed; report it instead of claiming success.
	if handle == 0 {
		return fmt.Errorf("dlopen returned NULL for %q", libPath)
	}
	inj.logf("dlopen returned handle 0x%x", handle)
	return nil
}

// validateLibPath enforces that the library path is usable inside the target (T29/T30).
// It must be non-empty and absolute, because the target resolves it within its own mount
// namespace and cwd; a relative path would be ambiguous.
func validateLibPath(p string) error {
	if p == "" {
		return errors.New("library path must not be empty")
	}
	if !filepath.IsAbs(p) {
		return fmt.Errorf("library path must be absolute (it is resolved in the target's namespace): %q", p)
	}
	if len(p) >= pageSize {
		return fmt.Errorf("library path too long: %d bytes", len(p))
	}
	return nil
}
