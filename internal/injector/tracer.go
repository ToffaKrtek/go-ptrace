package injector

type sysCalls interface {
	PtraceAttach(pid int) error
	PtraceDetach(pid int) error
}

type Tracer interface {
	Attach() error
	Detach() error
}

type ptracer struct {
	pid int
	sys sysCalls
}

func (t *ptracer) Attach() error {
	return t.sys.PtraceAttach(t.pid)
}

func (t *ptracer) Detach() error {
	return t.sys.PtraceDetach(t.pid)
}
