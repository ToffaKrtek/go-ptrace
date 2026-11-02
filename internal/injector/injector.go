package injector

type injector struct {
	tracer Tracer
}

func (i *injector) Inject(pid int) error {
	return nil
}
