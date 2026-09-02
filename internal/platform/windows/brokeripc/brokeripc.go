package brokeripc

import (
	"context"
	"fmt"
	"io"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
)

const Name = `\\.\pipe\agent-workstation-gateway-v1`

type Error struct {
	Rule  string
	Cause error
}

func (failure *Error) Error() string {
	return fmt.Sprintf("Windows broker IPC failed: %s", failure.Rule)
}

func (failure *Error) Unwrap() error { return failure.Cause }

type Server struct {
	native *serverNative
}

type Conn struct {
	native *connNative
}

func NewServer(configuration installconfig.Config) (*Server, error) {
	native, err := newServerNative(configuration)
	if err != nil {
		return nil, err
	}
	return &Server{native: native}, nil
}

func (server *Server) Accept(ctx context.Context) (*Conn, error) {
	if server == nil || server.native == nil {
		return nil, ipcError("server-invalid")
	}
	native, err := server.native.accept(ctx)
	if err != nil {
		return nil, err
	}
	return &Conn{native: native}, nil
}

func (server *Server) Close() error {
	if server == nil || server.native == nil {
		return nil
	}
	return server.native.close()
}

func Dial(ctx context.Context) (*Conn, error) {
	native, err := dialNative(ctx)
	if err != nil {
		return nil, err
	}
	return &Conn{native: native}, nil
}

func (connection *Conn) Read(buffer []byte) (int, error) {
	if connection == nil || connection.native == nil {
		return 0, ipcError("connection-invalid")
	}
	return connection.native.read(buffer)
}

func (connection *Conn) Write(buffer []byte) (int, error) {
	if connection == nil || connection.native == nil {
		return 0, ipcError("connection-invalid")
	}
	return connection.native.write(buffer)
}

func (connection *Conn) Close() error {
	if connection == nil || connection.native == nil {
		return nil
	}
	return connection.native.close()
}

func ipcError(rule string) error {
	return &Error{Rule: rule}
}

func ipcCause(rule string, cause error) error {
	return &Error{Rule: rule, Cause: cause}
}

var _ io.ReadWriteCloser = (*Conn)(nil)
