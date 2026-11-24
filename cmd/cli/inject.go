package main

import (
	"github.com/ToffaKrtek/go-ptrace/internal/injector"
)

func inject(pid int, libPath string) error {
	tracer := injector.NewTracer(pid)
	inj := injector.NewInjector(tracer)
	return inj.InjectLibrary(pid, libPath)
}
