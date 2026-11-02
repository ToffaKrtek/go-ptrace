package injector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

type mockTracer struct {
	attachErr error
}

func (m *mockTracer) Attach() error {
	return m.attachErr
}

func (m *mockTracer) Detach() error {
	return nil
}

func TestInjectorAttachEPERM(t *testing.T) {
	mock := &mockTracer{attachErr: unix.EPERM}
	inj := &injector{tracer: mock}
	err := inj.Inject(1234)
	assert.Error(t, err)
}
