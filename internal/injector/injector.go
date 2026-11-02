package injector

import "fmt"

type injector struct {
	tracer Tracer
}

func (i *injector) Inject(pid int) error {
	if err := i.tracer.Attach(); err != nil {
		return fmt.Errorf("attach to process: %w", err)
	}
	return nil
}
