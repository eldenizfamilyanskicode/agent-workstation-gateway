//go:build windows

// Package brokerservice hosts the narrow Windows broker under the Service
// Control Manager. Service installation and mutation remain separate.
package brokerservice

import (
	"context"
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/brokerhost"
)

const (
	Name = "AgentWorkstationGatewayBroker"

	startupWaitHintMilliseconds  = 15_000
	shutdownWaitHintMilliseconds = 30_000
	exitStartupFailure           = 1
	exitRuntimeFailure           = 2
	exitShutdownFailure          = 3
)

type brokerRuntime interface {
	HandleOne(context.Context) error
	Close() error
}

type runtimeFactory func(string, string) (brokerRuntime, error)

type serviceHandler struct {
	installationRoot string
	gatewaySourceSHA string
	newRuntime       runtimeFactory
	recoverable      func(error) bool
}

type Error struct {
	Rule  string
	Cause error
}

func (failure *Error) Error() string {
	return fmt.Sprintf("Windows broker service failed: %s", failure.Rule)
}

func (failure *Error) Unwrap() error { return failure.Cause }

// Run dispatches the fixed broker service. It rejects interactive execution
// and any process identity other than LocalSystem before protected state is
// loaded or a listener is created.
func Run(installationRoot string, gatewaySourceSHA string) error {
	if err := validateStartupInputs(installationRoot, gatewaySourceSHA); err != nil {
		return err
	}
	isService, err := svc.IsWindowsService()
	if err != nil {
		return serviceCause("scm-context-query-failed", err)
	}
	if !isService {
		return serviceError("scm-context-required")
	}
	if err := validateLocalSystemIdentity(); err != nil {
		return err
	}
	handler := &serviceHandler{
		installationRoot: installationRoot,
		gatewaySourceSHA: gatewaySourceSHA,
		newRuntime: func(root string, sourceSHA string) (brokerRuntime, error) {
			return brokerhost.New(root, sourceSHA)
		},
		recoverable: brokerhost.IsRecoverableConnectionError,
	}
	if err := svc.Run(Name, handler); err != nil {
		return serviceCause("scm-dispatch-failed", err)
	}
	return nil
}

func validateStartupInputs(installationRoot string, gatewaySourceSHA string) error {
	if _, err := installplan.WindowsLayout(installationRoot); err != nil {
		return serviceCause("installation-root-invalid", err)
	}
	if !lowerHexSourceSHA(gatewaySourceSHA) {
		return serviceError("gateway-source-sha-invalid")
	}
	return nil
}

func validateLocalSystemIdentity() error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return serviceCause("process-token-user-query-failed", err)
	}
	return validateLocalSystemSID(user.User.Sid)
}

func validateLocalSystemSID(actual *windows.SID) error {
	if actual == nil || !actual.IsValid() {
		return serviceError("process-token-user-invalid")
	}
	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil || localSystem == nil || !localSystem.IsValid() {
		return serviceCause("local-system-sid-create-failed", err)
	}
	if !actual.Equals(localSystem) {
		return serviceError("local-system-identity-required")
	}
	return nil
}

func (handler *serviceHandler) Execute(
	args []string,
	requests <-chan svc.ChangeRequest,
	statuses chan<- svc.Status,
) (bool, uint32) {
	statuses <- svc.Status{
		State: svc.StartPending, CheckPoint: 1, WaitHint: startupWaitHintMilliseconds,
	}
	if len(args) != 1 || args[0] != Name || handler == nil || handler.newRuntime == nil || handler.recoverable == nil {
		return true, exitStartupFailure
	}
	runtime, err := handler.newRuntime(handler.installationRoot, handler.gatewaySourceSHA)
	if err != nil || runtime == nil {
		if runtime != nil {
			_ = runtime.Close()
		}
		return true, exitStartupFailure
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, runtime, handler.recoverable)
	}()
	running := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	statuses <- running
	for {
		select {
		case runErr := <-done:
			closeErr := runtime.Close()
			if runErr != nil || closeErr != nil {
				return true, exitRuntimeFailure
			}
			return true, exitRuntimeFailure
		case request, open := <-requests:
			if !open {
				return stopService(statuses, cancel, runtime, done)
			}
			switch request.Cmd {
			case svc.Stop, svc.Shutdown:
				return stopService(statuses, cancel, runtime, done)
			case svc.Interrogate:
				statuses <- running
			default:
				statuses <- running
			}
		}
	}
}

func serve(ctx context.Context, runtime brokerRuntime, recoverable func(error) bool) error {
	if ctx == nil || runtime == nil || recoverable == nil {
		return serviceError("runtime-loop-invalid")
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		err := runtime.HandleOne(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err == nil || recoverable(err) {
			continue
		}
		return serviceCause("runtime-loop-failed", err)
	}
}

func stopService(
	statuses chan<- svc.Status,
	cancel context.CancelFunc,
	runtime brokerRuntime,
	done <-chan error,
) (bool, uint32) {
	statuses <- svc.Status{
		State: svc.StopPending, CheckPoint: 2, WaitHint: shutdownWaitHintMilliseconds,
	}
	cancel()
	closeErr := runtime.Close()
	runErr := <-done
	if closeErr != nil || runErr != nil {
		return true, exitShutdownFailure
	}
	return false, 0
}

func lowerHexSourceSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func serviceError(rule string) error { return &Error{Rule: rule} }

func serviceCause(rule string, cause error) error { return &Error{Rule: rule, Cause: cause} }

var _ svc.Handler = (*serviceHandler)(nil)
