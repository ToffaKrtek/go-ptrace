package injector

import "fmt"

type injector struct {
	tracer Tracer
}

func (i *injector) Inject(pid int, shellcode []byte, libPath string) error {
	if err := i.tracer.Attach(); err != nil {
		return fmt.Errorf("attach to process: %w", err)
	}
	defer i.tracer.Detach()

	strAddr, err := i.tracer.Mmap(len(libPath) + 1)
	if err != nil {
		return fmt.Errorf("mmap for lib path: %w", err)
	}
	shellcodeAddr, err := i.tracer.Mmap(len(shellcode))
	if err != nil {
		return fmt.Errorf("mmap for shellcode: %w", err)
	}
	payload := append([]byte(libPath), 0)
	if err := i.tracer.PokeData(strAddr, payload); err != nil {
		return fmt.Errorf("poke lib path: %w", err)
	}

	if err := i.tracer.PokeText(shellcodeAddr, shellcode); err != nil {
		return fmt.Errorf("poke shellcode: %w", err)
	}
	regs, err := i.tracer.GetRegs()
	if err != nil {
		return fmt.Errorf("get regs: %w", err)
	}

	regs.Rip = uint64(shellcodeAddr)
	regs.Rdi = uint64(strAddr)

	if err := i.tracer.SetRegs(regs); err != nil {
		return fmt.Errorf("set regs: %w", err)
	}

	if err := i.tracer.Cont(); err != nil {
		return fmt.Errorf("cont: %w", err)
	}

	if err := i.tracer.Wait(); err != nil {
		return fmt.Errorf("wait: %w", err)
	}

	return nil
}
