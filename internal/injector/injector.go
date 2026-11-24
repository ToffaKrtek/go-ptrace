package injector

import "fmt"

const rtldNow = 0x2

type injector struct {
	tracer Tracer
}

// Injector is the public interface for library injection.
type Injector struct {
	Tracer Tracer
}

// NewInjector creates a new Injector with the given Tracer.
func NewInjector(t Tracer) *Injector {
	return &Injector{Tracer: t}
}

// InjectLibrary injects a shared library into a target process by PID.
// It automatically finds dlopen's address and generates the shellcode.
func (inj *Injector) InjectLibrary(pid int, libPath string) error {
	dlopenAddr, err := FindDlopenAddr(pid)
	if err != nil {
		return fmt.Errorf("find dlopen: %w", err)
	}

	shellcode, err := GenerateDlopenShellcode(dlopenAddr, rtldNow)
	if err != nil {
		return fmt.Errorf("generate shellcode: %w", err)
	}

	return inj.Inject(pid, shellcode, libPath)
}

// Inject injects a shared library into a target process by PID.
// The shellcode must be pre-generated (e.g., via GenerateDlopenShellcode).
func (inj *Injector) Inject(pid int, shellcode []byte, libPath string) error {
	if err := inj.Tracer.Attach(); err != nil {
		return fmt.Errorf("attach to process: %w", err)
	}
	defer inj.Tracer.Detach()

	strAddr, err := inj.Tracer.Mmap(len(libPath) + 1)
	if err != nil {
		return fmt.Errorf("mmap for lib path: %w", err)
	}
	shellcodeAddr, err := inj.Tracer.Mmap(len(shellcode))
	if err != nil {
		return fmt.Errorf("mmap for shellcode: %w", err)
	}
	payload := append([]byte(libPath), 0)
	if err := inj.Tracer.PokeData(strAddr, payload); err != nil {
		return fmt.Errorf("poke lib path: %w", err)
	}

	if err := inj.Tracer.PokeText(shellcodeAddr, shellcode); err != nil {
		return fmt.Errorf("poke shellcode: %w", err)
	}
	regs, err := inj.Tracer.GetRegs()
	if err != nil {
		return fmt.Errorf("get regs: %w", err)
	}

	regs.Rip = uint64(shellcodeAddr)
	regs.Rdi = uint64(strAddr)

	if err := inj.Tracer.SetRegs(regs); err != nil {
		return fmt.Errorf("set regs: %w", err)
	}

	if err := inj.Tracer.Cont(); err != nil {
		return fmt.Errorf("cont: %w", err)
	}

	if err := inj.Tracer.Wait(); err != nil {
		return fmt.Errorf("wait: %w", err)
	}

	return nil
}


