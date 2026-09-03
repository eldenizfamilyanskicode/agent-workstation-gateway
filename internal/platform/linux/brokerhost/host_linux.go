//go:build linux

package brokerhost

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/brokersession"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionrun"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/linux/artifact"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/linux/brokeripc"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/linux/pathresolver"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/linux/process"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

type connection interface {
	brokersession.ContextTransport
	Close() error
}

type Runtime struct {
	listener *brokeripc.Server
	handler  *brokersession.Session
	runner   *executionrun.Runner
	mu       sync.Mutex
	active   connection
	closed   bool
	once     sync.Once
	closeErr error
}

type Error struct {
	Rule  string
	Cause error
}

func (failure *Error) Error() string {
	return fmt.Sprintf("Linux broker host failed: %s", failure.Rule)
}
func (failure *Error) Unwrap() error { return failure.Cause }

func New(installationRoot, gatewaySourceSHA string) (*Runtime, error) {
	if os.Geteuid() != 0 {
		return nil, hostError("root-broker-required")
	}
	layout, err := installplan.LinuxLayout(installationRoot)
	if err != nil {
		return nil, hostCause("installation-root-invalid", err)
	}
	for _, directory := range []string{layout.Root, layout.BinDirectory, layout.StateDirectory} {
		if validateProtected(directory, true, 0) != nil {
			return nil, hostError("protected-directory-invalid")
		}
	}
	if validateProtected(layout.InstallationConfig, false, installconfig.MaxConfigBytes) != nil {
		return nil, hostError("installation-config-invalid")
	}
	encoded, err := os.ReadFile(layout.InstallationConfig)
	if err != nil {
		return nil, hostCause("installation-config-read-failed", err)
	}
	defer clear(encoded)
	configuration, err := installconfig.Decode(encoded)
	if err != nil || configuration.Platform != platformpath.Linux {
		return nil, hostError("installation-config-invalid")
	}
	if err := validateSeparation(layout, configuration); err != nil {
		return nil, err
	}
	if err := process.EnableChildSubreaper(); err != nil {
		return nil, hostCause("subreaper-unavailable", err)
	}
	launcher, err := process.NewLauncher()
	if err != nil {
		return nil, hostCause("launcher-create-failed", err)
	}
	collector, err := artifact.New(configuration)
	if err != nil {
		return nil, hostCause("collector-create-failed", err)
	}
	runner, err := executionrun.New(launcher, collector, executionrun.Options{})
	if err != nil {
		return nil, hostCause("runner-create-failed", err)
	}
	session, err := brokersession.New(configuration, nil, pathresolver.Resolver{}, runner, gatewaySourceSHA, brokersession.Options{})
	if err != nil {
		return nil, hostCause("session-create-failed", err)
	}
	listener, err := brokeripc.NewServer(configuration)
	if err != nil {
		return nil, hostCause("listener-create-failed", err)
	}
	return &Runtime{listener: listener, handler: session, runner: runner}, nil
}

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

func (host *Runtime) Close() error {
	if host == nil {
		return nil
	}
	host.once.Do(func() {
		host.mu.Lock()
		host.closed = true
		active := host.active
		host.mu.Unlock()
		if host.listener != nil {
			host.closeErr = host.listener.Close()
		}
		if active != nil {
			host.closeErr = errors.Join(host.closeErr, active.Close())
		}
		if host.runner != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			host.closeErr = errors.Join(host.closeErr, host.runner.Close(ctx))
			cancel()
		}
	})
	return host.closeErr
}

func IsRecoverableConnectionError(err error) bool {
	var failure *Error
	if !errors.As(err, &failure) {
		return false
	}
	if failure.Rule == "connection-session-failed" {
		return true
	}
	var ipcFailure *brokeripc.Error
	return failure.Rule == "connection-accept-failed" && errors.As(failure.Cause, &ipcFailure) && ipcFailure.Rule == "peer-uid-mismatch"
}

func validateSeparation(layout installplan.Layout, configuration installconfig.Config) error {
	for _, root := range configuration.ApprovedRoots {
		if platformpath.Overlaps(platformpath.Linux, layout.Root, root) || platformpath.Overlaps(platformpath.Linux, layout.RunnerRoot, root) {
			return hostError("protected-root-overlap")
		}
	}
	if platformpath.Overlaps(platformpath.Linux, layout.Root, configuration.ProfileRoot) ||
		platformpath.Overlaps(platformpath.Linux, layout.Root, configuration.TempRoot) {
		return hostError("execution-state-overlap")
	}
	return nil
}

func validateProtected(path string, directory bool, maximum int) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory {
		return hostError("protected-object-invalid")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 || (!directory && (info.Size() <= 0 || info.Size() > int64(maximum))) {
		return hostError("protected-owner-invalid")
	}
	if directory && info.Mode().Perm()&0o022 != 0 || !directory && info.Mode().Perm()&0o077 != 0 {
		return hostError("protected-mode-invalid")
	}
	return nil
}

func hostError(rule string) error              { return &Error{Rule: rule} }
func hostCause(rule string, cause error) error { return &Error{Rule: rule, Cause: cause} }

func clear(content []byte) {
	for index := range content {
		content[index] = 0
	}
}
