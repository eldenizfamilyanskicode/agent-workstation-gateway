//go:build windows

package servicectl

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/brokerservice"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/runnerservice"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/serviceinstall"
)

const transitionTimeout = 30 * time.Second

type Status struct {
	BrokerRunning bool
	RunnerRunning bool
}

type Error struct{ Rule string }

func (failure *Error) Error() string {
	return fmt.Sprintf("Windows service control failed: %s", failure.Rule)
}

func Start(ctx context.Context) error {
	manager, err := openManager()
	if err != nil {
		return serviceError("scm-connect-failed")
	}
	defer windows.CloseServiceHandle(manager)
	broker, err := openService(manager, brokerservice.Name, windows.SERVICE_START|windows.SERVICE_QUERY_STATUS|windows.SERVICE_STOP)
	if err != nil {
		return serviceError("broker-open-failed")
	}
	defer broker.Close()
	if err := startOne(ctx, broker); err != nil {
		return serviceError("broker-start-failed")
	}
	runner, err := openService(manager, runnerservice.Name, windows.SERVICE_START|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		_ = stopOne(context.Background(), broker)
		return serviceError("runner-open-failed")
	}
	defer runner.Close()
	if err := startOne(ctx, runner); err != nil {
		_ = stopOne(context.Background(), broker)
		return serviceError("runner-start-failed")
	}
	return nil
}

func Stop(ctx context.Context) error {
	manager, err := openManager()
	if err != nil {
		return serviceError("scm-connect-failed")
	}
	defer windows.CloseServiceHandle(manager)
	runner, err := openService(manager, runnerservice.Name, windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return serviceError("runner-open-failed")
	}
	runnerErr := stopOne(ctx, runner)
	runnerCloseErr := runner.Close()
	broker, err := openService(manager, brokerservice.Name, windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return serviceError("broker-open-failed")
	}
	brokerErr := stopOne(ctx, broker)
	brokerCloseErr := broker.Close()
	if runnerErr != nil || runnerCloseErr != nil || brokerErr != nil || brokerCloseErr != nil {
		return serviceError("service-stop-failed")
	}
	return nil
}

func Inspect(ctx context.Context) (Status, error) {
	if ctx == nil {
		return Status{}, serviceError("context-required")
	}
	manager, err := openManager()
	if err != nil {
		return Status{}, serviceError("scm-connect-failed")
	}
	defer windows.CloseServiceHandle(manager)
	broker, err := queryRunning(ctx, manager, brokerservice.Name)
	if err != nil {
		return Status{}, serviceError("broker-status-failed")
	}
	runner, err := queryRunning(ctx, manager, runnerservice.Name)
	if err != nil {
		return Status{}, serviceError("runner-status-failed")
	}
	return Status{BrokerRunning: broker, RunnerRunning: runner}, nil
}

func Delete(ctx context.Context, installationRoot string, controlAccount string) error {
	if serviceinstall.VerifyFixedService(installationRoot) != nil ||
		runnerservice.VerifyFixedService(installationRoot, controlAccount) != nil {
		return serviceError("installed-service-policy-invalid")
	}
	if err := Stop(ctx); err != nil {
		return err
	}
	manager, err := openManager()
	if err != nil {
		return serviceError("scm-connect-failed")
	}
	defer windows.CloseServiceHandle(manager)
	for _, name := range []string{runnerservice.Name, brokerservice.Name} {
		service, err := openService(manager, name, windows.DELETE|windows.SERVICE_QUERY_STATUS)
		if err != nil {
			return serviceError("service-delete-open-failed")
		}
		deleteErr := service.Delete()
		closeErr := service.Close()
		if deleteErr != nil || closeErr != nil {
			return serviceError("service-delete-failed")
		}
	}
	return nil
}

func openManager() (windows.Handle, error) {
	return windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
}

func openService(manager windows.Handle, name string, access uint32) (*mgr.Service, error) {
	pointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	handle, err := windows.OpenService(manager, pointer, access)
	if err != nil {
		return nil, err
	}
	return &mgr.Service{Name: name, Handle: handle}, nil
}

func startOne(ctx context.Context, service *mgr.Service) error {
	if ctx == nil || service == nil {
		return serviceError("dependency-required")
	}
	status, err := service.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Running {
		return nil
	}
	if status.State == svc.Stopped {
		if err := service.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			return err
		}
	}
	return waitFor(ctx, service, svc.Running)
}

func stopOne(ctx context.Context, service *mgr.Service) error {
	if ctx == nil || service == nil {
		return serviceError("dependency-required")
	}
	status, err := service.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Stopped {
		return nil
	}
	if _, err := service.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return err
	}
	return waitFor(ctx, service, svc.Stopped)
}

func waitFor(ctx context.Context, service *mgr.Service, expected svc.State) error {
	deadline := time.NewTimer(transitionTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := service.Query()
		if err != nil {
			return err
		}
		if status.State == expected {
			return nil
		}
		if expected == svc.Running && status.State == svc.Stopped {
			return serviceError("service-returned-to-stopped")
		}
		select {
		case <-ctx.Done():
			return serviceError("context-cancelled")
		case <-deadline.C:
			return serviceError("transition-timeout")
		case <-ticker.C:
		}
	}
}

func queryRunning(ctx context.Context, manager windows.Handle, name string) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}
	service, err := openService(manager, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false, err
	}
	defer service.Close()
	status, err := service.Query()
	return status.State == svc.Running, err
}

func serviceError(rule string) error { return &Error{Rule: rule} }
