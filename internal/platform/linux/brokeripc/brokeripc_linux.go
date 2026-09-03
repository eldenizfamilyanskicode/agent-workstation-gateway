//go:build linux

package brokeripc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

const (
	SocketDirectory = "/run/agent-workstation-gateway"
	SocketPath      = SocketDirectory + "/broker.sock"
)

type Error struct {
	Rule  string
	Cause error
}

func (failure *Error) Error() string { return fmt.Sprintf("Linux broker IPC failed: %s", failure.Rule) }
func (failure *Error) Unwrap() error { return failure.Cause }

type Server struct {
	listener *net.UnixListener
	uid      uint32
	gid      int
	mu       sync.Mutex
	closed   bool
}

type Conn struct{ connection *net.UnixConn }

func NewServer(configuration installconfig.Config) (*Server, error) {
	if os.Geteuid() != 0 || configuration.Platform != platformpath.Linux || installconfig.Validate(configuration) != nil {
		return nil, ipcError("installed-configuration-invalid")
	}
	uid, err := parseID(configuration.ControlIdentity.Identifier, "uid:")
	if err != nil {
		return nil, ipcError("control-uid-invalid")
	}
	gid, err := parseID(configuration.ControlIdentity.PrimaryGroupIdentifier, "gid:")
	if err != nil {
		return nil, ipcError("control-gid-invalid")
	}
	if err := ensureSocketDirectory(int(gid)); err != nil {
		return nil, err
	}
	if err := removeOwnedStaleSocket(); err != nil {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: SocketPath, Net: "unix"})
	if err != nil {
		return nil, ipcCause("socket-listen-failed", err)
	}
	server := &Server{listener: listener, uid: uid, gid: int(gid)}
	if err := os.Chown(SocketPath, 0, int(gid)); err != nil || os.Chmod(SocketPath, 0o660) != nil || verifySocket(int(gid)) != nil {
		_ = listener.Close()
		_ = os.Remove(SocketPath)
		return nil, ipcError("socket-policy-failed")
	}
	return server, nil
}

func (server *Server) Accept(ctx context.Context) (*Conn, error) {
	if server == nil || server.listener == nil || ctx == nil {
		return nil, ipcError("server-invalid")
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, ipcCause("accept-cancelled", err)
		}
		_ = server.listener.SetDeadline(time.Now().Add(250 * time.Millisecond))
		connection, err := server.listener.AcceptUnix()
		if err != nil {
			var networkError net.Error
			if errors.As(err, &networkError) && networkError.Timeout() {
				continue
			}
			return nil, ipcCause("accept-failed", err)
		}
		uid, err := peerUID(connection)
		if err != nil || uid != server.uid {
			_ = connection.Close()
			return nil, ipcError("peer-uid-mismatch")
		}
		return &Conn{connection: connection}, nil
	}
}

func (server *Server) Close() error {
	if server == nil || server.listener == nil {
		return nil
	}
	server.mu.Lock()
	if server.closed {
		server.mu.Unlock()
		return nil
	}
	server.closed = true
	server.mu.Unlock()
	err := server.listener.Close()
	if removeErr := removeOwnedStaleSocket(); removeErr != nil && err == nil {
		err = removeErr
	}
	return err
}

func Dial(ctx context.Context) (*Conn, error) {
	if ctx == nil {
		return nil, ipcError("dial-context-invalid")
	}
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "unix", SocketPath)
	if err != nil {
		return nil, ipcCause("dial-failed", err)
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		return nil, ipcError("dial-transport-invalid")
	}
	return &Conn{connection: unixConnection}, nil
}

func (connection *Conn) Read(buffer []byte) (int, error) {
	return connection.ReadContext(context.Background(), buffer)
}

func (connection *Conn) ReadContext(ctx context.Context, buffer []byte) (int, error) {
	if connection == nil || connection.connection == nil || ctx == nil {
		return 0, ipcError("connection-invalid")
	}
	return withDeadline(ctx, connection.connection.SetReadDeadline, func() (int, error) { return connection.connection.Read(buffer) })
}

func (connection *Conn) Write(buffer []byte) (int, error) {
	return connection.WriteContext(context.Background(), buffer)
}

func (connection *Conn) WriteContext(ctx context.Context, buffer []byte) (int, error) {
	if connection == nil || connection.connection == nil || ctx == nil {
		return 0, ipcError("connection-invalid")
	}
	return withDeadline(ctx, connection.connection.SetWriteDeadline, func() (int, error) { return connection.connection.Write(buffer) })
}

func (connection *Conn) Close() error {
	if connection == nil || connection.connection == nil {
		return nil
	}
	return connection.connection.Close()
}

func withDeadline(ctx context.Context, set func(time.Time) error, operation func() (int, error)) (int, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Time{}
	}
	if err := set(deadline); err != nil {
		return 0, err
	}
	count, err := operation()
	if err != nil && ctx.Err() != nil {
		return count, ctx.Err()
	}
	return count, err
}

func peerUID(connection *net.UnixConn) (uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credential *unix.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credential, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if controlErr != nil || credential == nil || credential.Pid <= 0 {
		return 0, controlErr
	}
	return credential.Uid, nil
}

func ensureSocketDirectory(gid int) error {
	if err := os.Mkdir(SocketDirectory, 0o750); err != nil && !errors.Is(err, os.ErrExist) {
		return ipcCause("socket-directory-create-failed", err)
	}
	if err := os.Chown(SocketDirectory, 0, gid); err != nil || os.Chmod(SocketDirectory, 0o750) != nil {
		return ipcError("socket-directory-policy-failed")
	}
	info, err := os.Lstat(SocketDirectory)
	if err != nil {
		return ipcCause("socket-directory-inspect-failed", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || int(stat.Gid) != gid || info.Mode().Perm() != 0o750 {
		return ipcError("socket-directory-verification-failed")
	}
	return nil
}

func verifySocket(gid int) error {
	info, err := os.Lstat(SocketPath)
	if err != nil {
		return ipcCause("socket-inspect-failed", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || stat.Uid != 0 || int(stat.Gid) != gid || info.Mode().Perm() != 0o660 {
		return ipcError("socket-verification-failed")
	}
	return nil
}

func removeOwnedStaleSocket() error {
	info, err := os.Lstat(SocketPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return ipcCause("socket-inspect-failed", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || stat.Uid != 0 || filepath.Dir(SocketPath) != SocketDirectory {
		return ipcError("stale-socket-not-owned")
	}
	if err := os.Remove(SocketPath); err != nil {
		return ipcCause("stale-socket-remove-failed", err)
	}
	return nil
}

func parseID(value, prefix string) (uint32, error) {
	if !strings.HasPrefix(value, prefix) {
		return 0, ipcError("identity-invalid")
	}
	parsed, err := strconv.ParseUint(strings.TrimPrefix(value, prefix), 10, 32)
	if err != nil || parsed == 0 || parsed == 4294967295 {
		return 0, ipcError("identity-invalid")
	}
	return uint32(parsed), nil
}

func ipcError(rule string) error              { return &Error{Rule: rule} }
func ipcCause(rule string, cause error) error { return &Error{Rule: rule, Cause: cause} }

var _ syscall.Conn = (*net.UnixConn)(nil)
