//go:build windows

// Package brokerhost composes the Windows broker's fixed protected state,
// restricted execution dependencies, authenticated pipe, and bounded session.
package brokerhost

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/brokersession"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionrun"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/artifact"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/brokeripc"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/pathresolver"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/process"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/protectedstate"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

type connection interface {
	brokersession.ContextTransport
	Close() error
}

type listener interface {
	Accept(context.Context) (connection, error)
	Close() error
}

type sessionHandler interface {
	Handle(context.Context, brokersession.ContextTransport) error
}

type dependencies struct {
	readProtected     func(string, int) ([]byte, error)
	validateProtected func(string, int) error
	systemDirectory   func() (string, error)
	listen            func(installconfig.Config) (listener, error)
}

// Runtime owns the fixed authenticated listener and the complete broker
// session dependency graph. It never accepts state or executable paths from a
// request.
type Runtime struct {
	listener listener
	handler  sessionHandler
	executor interface {
		Close(context.Context) error
	}

	mu        sync.Mutex
	active    connection
	closed    bool
	closeOnce sync.Once
	closeErr  error
}

type Error struct {
	Rule  string
	Cause error
}

func (failure *Error) Error() string {
	return fmt.Sprintf("Windows broker host failed: %s", failure.Rule)
}

func (failure *Error) Unwrap() error { return failure.Cause }

// New loads only installation-root-derived protected state and composes the
// real Windows broker dependencies. It has no current-user execution fallback.
func New(installationRoot string, gatewaySourceSHA string) (*Runtime, error) {
	return newRuntime(installationRoot, gatewaySourceSHA, dependencies{
		readProtected:     protectedstate.ReadExactFile,
		validateProtected: protectedstate.ValidateExactFile,
		systemDirectory:   windows.GetSystemWindowsDirectory,
		listen:            newNativeListener,
	})
}

func newRuntime(installationRoot string, gatewaySourceSHA string, deps dependencies) (*Runtime, error) {
	if deps.readProtected == nil || deps.validateProtected == nil || deps.systemDirectory == nil || deps.listen == nil {
		return nil, hostError("startup-dependency-required")
	}
	layout, err := installplan.WindowsLayout(installationRoot)
	if err != nil {
		return nil, hostCause("installation-root-invalid", err)
	}
	encoded, err := deps.readProtected(layout.InstallationConfig, installconfig.MaxConfigBytes)
	if err != nil {
		return nil, hostCause("installation-config-read-failed", err)
	}
	defer zero(encoded)
	configuration, err := installconfig.Decode(encoded)
	if err != nil {
		return nil, hostCause("installation-config-invalid", err)
	}
	if err := validateAuthoritySeparation(layout, configuration); err != nil {
		return nil, err
	}
	if err := deps.validateProtected(layout.ExecutionCredential, process.MaxProtectedCredentialBytes); err != nil {
		return nil, hostCause("execution-credential-invalid", err)
	}
	safeBase, err := trustedWindowsEnvironment(deps.systemDirectory)
	if err != nil {
		return nil, err
	}
	tokens, err := process.NewFileTokenSource(configuration.ExecutionIdentity, layout.ExecutionCredential)
	if err != nil {
		return nil, hostCause("token-source-create-failed", err)
	}
	launcher, err := process.NewLauncher(tokens)
	if err != nil {
		return nil, hostCause("launcher-create-failed", err)
	}
	collector, err := artifact.New(configuration, tokens)
	if err != nil {
		return nil, hostCause("collector-create-failed", err)
	}
	runner, err := executionrun.New(launcher, collector, executionrun.Options{})
	if err != nil {
		return nil, hostCause("runner-create-failed", err)
	}
	session, err := brokersession.New(
		configuration, safeBase, pathresolver.Resolver{}, runner, gatewaySourceSHA, brokersession.Options{},
	)
	if err != nil {
		return nil, hostCause("session-create-failed", err)
	}
	server, err := deps.listen(configuration)
	if err != nil || server == nil {
		if server != nil {
			_ = server.Close()
		}
		return nil, hostCause("listener-create-failed", err)
	}
	return &Runtime{listener: server, handler: session, executor: runner}, nil
}

func validateAuthoritySeparation(layout installplan.Layout, configuration installconfig.Config) error {
	for _, approvedRoot := range configuration.ApprovedRoots {
		if platformpath.Overlaps(platformpath.Windows, layout.Root, approvedRoot) {
			return hostError("installation-overlaps-approved-root")
		}
	}
	if platformpath.Overlaps(platformpath.Windows, layout.Root, configuration.ProfileRoot) {
		return hostError("installation-overlaps-profile-root")
	}
	if platformpath.Overlaps(platformpath.Windows, layout.Root, configuration.TempRoot) {
		return hostError("installation-overlaps-temp-root")
	}
	return nil
}

func trustedWindowsEnvironment(systemDirectory func() (string, error)) ([]string, error) {
	directory, err := systemDirectory()
	if err != nil {
		return nil, hostCause("system-directory-query-failed", err)
	}
	if len(directory) >= 2 && directory[1] == ':' && directory[0] >= 'a' && directory[0] <= 'z' {
		directory = strings.ToUpper(directory[:1]) + directory[1:]
	}
	if platformpath.ValidateAbsolute(platformpath.Windows, directory) != nil {
		return nil, hostError("system-directory-invalid")
	}
	return []string{"SystemRoot=" + directory, "WINDIR=" + directory}, nil
}

// HandleOne accepts one authenticated control connection, executes one bounded
// session, and closes that connection on every return path.
func (host *Runtime) HandleOne(ctx context.Context) (resultErr error) {
	if host == nil || host.listener == nil || host.handler == nil || ctx == nil {
		return hostError("runtime-invalid")
	}
	host.mu.Lock()
	closed := host.closed
	host.mu.Unlock()
	if closed {
		return hostError("runtime-closed")
	}
	client, err := host.listener.Accept(ctx)
	if err != nil || client == nil {
		return hostCause("connection-accept-failed", err)
	}
	host.mu.Lock()
	if host.closed {
		host.mu.Unlock()
		_ = client.Close()
		return hostError("runtime-closed")
	}
	host.active = client
	host.mu.Unlock()
	defer func() {
		host.mu.Lock()
		if host.active == client {
			host.active = nil
		}
		host.mu.Unlock()
		if err := client.Close(); err != nil {
			resultErr = errors.Join(resultErr, hostCause("connection-close-failed", err))
		}
	}()
	if err := host.handler.Handle(ctx, client); err != nil {
		return hostCause("connection-session-failed", err)
	}
	return nil
}

// Close stops future accepts and interrupts the active owned connection. It is
// idempotent and lets a service stop unblock both accept and session I/O.
func (host *Runtime) Close() error {
	if host == nil || host.listener == nil {
		return nil
	}
	host.closeOnce.Do(func() {
		host.mu.Lock()
		host.closed = true
		active := host.active
		host.mu.Unlock()
		if err := host.listener.Close(); err != nil {
			host.closeErr = hostCause("listener-close-failed", err)
		}
		if active != nil {
			if err := active.Close(); err != nil {
				host.closeErr = errors.Join(host.closeErr, hostCause("active-connection-close-failed", err))
			}
		}
		if host.executor != nil {
			shutdownContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			if err := host.executor.Close(shutdownContext); err != nil {
				host.closeErr = errors.Join(host.closeErr, hostCause("background-cleanup-failed", err))
			}
			cancel()
		}
	})
	return host.closeErr
}

// IsRecoverableConnectionError reports whether a completed HandleOne failure
// is confined to one closed peer/session and the listener may safely accept the
// next client. Listener infrastructure and connection-close failures are never
// recoverable.
func IsRecoverableConnectionError(err error) bool {
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !IsRecoverableConnectionError(child) {
				return false
			}
		}
		return true
	}
	failure, ok := err.(*Error)
	if !ok {
		return false
	}
	switch failure.Rule {
	case "connection-session-failed":
		return true
	case "connection-accept-failed":
		ipcFailure, ok := failure.Cause.(*brokeripc.Error)
		if !ok {
			return false
		}
		return ipcFailure.Rule == "authentication-preface-invalid" || ipcFailure.Rule == "peer-sid-mismatch"
	default:
		return false
	}
}

type nativeListener struct {
	server *brokeripc.Server
}

func newNativeListener(configuration installconfig.Config) (listener, error) {
	server, err := brokeripc.NewServer(configuration)
	if err != nil {
		return nil, err
	}
	return &nativeListener{server: server}, nil
}

func (native *nativeListener) Accept(ctx context.Context) (connection, error) {
	return native.server.Accept(ctx)
}

func (native *nativeListener) Close() error { return native.server.Close() }

func hostError(rule string) error { return &Error{Rule: rule} }

func hostCause(rule string, cause error) error { return &Error{Rule: rule, Cause: cause} }

//go:noinline
func zero(content []byte) {
	for index := range content {
		content[index] = 0
	}
	runtime.KeepAlive(content)
}
