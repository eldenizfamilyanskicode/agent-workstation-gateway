//go:build !windows

package brokeripc

import (
	"context"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
)

type serverNative struct{}
type connNative struct{}

func newServerNative(installconfig.Config) (*serverNative, error) {
	return nil, ipcError("platform-unsupported")
}

func (*serverNative) accept(context.Context) (*connNative, error) {
	return nil, ipcError("platform-unsupported")
}

func (*serverNative) close() error { return nil }

func dialNative(context.Context) (*connNative, error) {
	return nil, ipcError("platform-unsupported")
}

func (*connNative) read([]byte) (int, error)  { return 0, ipcError("platform-unsupported") }
func (*connNative) write([]byte) (int, error) { return 0, ipcError("platform-unsupported") }
func (*connNative) close() error              { return nil }
