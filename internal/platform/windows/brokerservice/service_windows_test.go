//go:build windows

package brokerservice

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

const testSourceSHA = "0123456789abcdef0123456789abcdef01234567"

type scriptedRuntime struct {
	mu       sync.Mutex
	results  []error
	block    chan struct{}
	started  chan struct{}
	startOne sync.Once
	closeOne sync.Once
	closeErr error
	calls    atomic.Int32
	closes   atomic.Int32
}

func (runtime *scriptedRuntime) HandleOne(ctx context.Context) error {
	call := int(runtime.calls.Add(1)) - 1
	runtime.mu.Lock()
	if call < len(runtime.results) {
		result := runtime.results[call]
		runtime.mu.Unlock()
		return result
	}
	block := runtime.block
	started := runtime.started
	runtime.mu.Unlock()
	if started != nil {
		runtime.startOne.Do(func() { close(started) })
	}
	if block == nil {
		<-ctx.Done()
		return ctx.Err()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-block:
		return ctx.Err()
	}
}

func (runtime *scriptedRuntime) Close() error {
	runtime.closes.Add(1)
	runtime.closeOne.Do(func() {
		if runtime.block != nil {
			close(runtime.block)
		}
	})
	return runtime.closeErr
}

func TestServiceHandlerReportsLifecycleAndOwnsStop(t *testing.T) {
	for _, command := range []svc.Cmd{svc.Stop, svc.Shutdown} {
		t.Run(commandName(command), func(t *testing.T) {
			runtime := &scriptedRuntime{block: make(chan struct{}), started: make(chan struct{})}
			handler := validHandler(runtime, func(error) bool { return false })
			requests := make(chan svc.ChangeRequest, 2)
			statuses := make(chan svc.Status, 8)
			result := executeAsync(handler, requests, statuses)

			assertStatus(t, readStatus(t, statuses), svc.StartPending, 0)
			assertStatus(t, readStatus(t, statuses), svc.Running, svc.AcceptStop|svc.AcceptShutdown)
			<-runtime.started
			requests <- svc.ChangeRequest{Cmd: svc.Interrogate}
			assertStatus(t, readStatus(t, statuses), svc.Running, svc.AcceptStop|svc.AcceptShutdown)
			requests <- svc.ChangeRequest{Cmd: command}
			assertStatus(t, readStatus(t, statuses), svc.StopPending, 0)
			exit := readExit(t, result)
			if exit.specific || exit.code != 0 {
				t.Fatalf("clean stop returned specific=%t code=%d", exit.specific, exit.code)
			}
			if runtime.closes.Load() != 1 {
				t.Fatalf("runtime closed %d times", runtime.closes.Load())
			}
		})
	}
}

func TestServiceHandlerContinuesOnlyRecoverableConnections(t *testing.T) {
	recoverableFailure := errors.New("synthetic recoverable connection")
	runtime := &scriptedRuntime{
		results: []error{recoverableFailure}, block: make(chan struct{}), started: make(chan struct{}),
	}
	handler := validHandler(runtime, func(err error) bool { return errors.Is(err, recoverableFailure) })
	requests := make(chan svc.ChangeRequest, 1)
	statuses := make(chan svc.Status, 4)
	result := executeAsync(handler, requests, statuses)
	assertStatus(t, readStatus(t, statuses), svc.StartPending, 0)
	assertStatus(t, readStatus(t, statuses), svc.Running, svc.AcceptStop|svc.AcceptShutdown)
	<-runtime.started
	if runtime.calls.Load() < 2 {
		t.Fatal("recoverable connection failure did not continue to the next accept")
	}
	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	assertStatus(t, readStatus(t, statuses), svc.StopPending, 0)
	exit := readExit(t, result)
	if exit.specific || exit.code != 0 {
		t.Fatal("recoverable connection failure changed clean service stop")
	}
}

func TestServiceHandlerTreatsRuntimeInfrastructureFailureAsTerminal(t *testing.T) {
	fatalFailure := errors.New("synthetic listener infrastructure failure")
	runtime := &scriptedRuntime{results: []error{fatalFailure}}
	handler := validHandler(runtime, func(error) bool { return false })
	statuses := make(chan svc.Status, 4)
	result := executeAsync(handler, make(chan svc.ChangeRequest), statuses)
	assertStatus(t, readStatus(t, statuses), svc.StartPending, 0)
	assertStatus(t, readStatus(t, statuses), svc.Running, svc.AcceptStop|svc.AcceptShutdown)
	exit := readExit(t, result)
	if !exit.specific || exit.code != exitRuntimeFailure {
		t.Fatalf("terminal runtime failure returned specific=%t code=%d", exit.specific, exit.code)
	}
	if runtime.closes.Load() != 1 {
		t.Fatal("terminal runtime failure did not close the runtime")
	}
}

func TestServiceHandlerFailsClosedBeforeRunning(t *testing.T) {
	tests := []struct {
		name string
		args []string
		new  runtimeFactory
	}{
		{name: "unexpected start arguments", args: []string{Name, "request-selected"}, new: func(string, string) (brokerRuntime, error) {
			t.Fatal("unexpected service arguments reached broker startup")
			return nil, nil
		}},
		{name: "startup failure", args: []string{Name}, new: func(string, string) (brokerRuntime, error) {
			return nil, errors.New("synthetic protected startup failure")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := &serviceHandler{
				installationRoot: `C:\ProgramData\AgentWorkstationGateway`, gatewaySourceSHA: testSourceSHA,
				newRuntime: test.new, recoverable: func(error) bool { return false },
			}
			statuses := make(chan svc.Status, 2)
			specific, code := handler.Execute(test.args, make(chan svc.ChangeRequest), statuses)
			assertStatus(t, readStatus(t, statuses), svc.StartPending, 0)
			if !specific || code != exitStartupFailure {
				t.Fatalf("startup denial returned specific=%t code=%d", specific, code)
			}
			select {
			case status := <-statuses:
				t.Fatalf("startup failure unexpectedly reported state %d", status.State)
			default:
			}
		})
	}
}

func TestServiceShutdownSurfacesOwnedCloseFailure(t *testing.T) {
	runtime := &scriptedRuntime{
		block: make(chan struct{}), started: make(chan struct{}), closeErr: errors.New("synthetic close failure"),
	}
	handler := validHandler(runtime, func(error) bool { return false })
	requests := make(chan svc.ChangeRequest, 1)
	statuses := make(chan svc.Status, 4)
	result := executeAsync(handler, requests, statuses)
	readStatus(t, statuses)
	readStatus(t, statuses)
	<-runtime.started
	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	assertStatus(t, readStatus(t, statuses), svc.StopPending, 0)
	exit := readExit(t, result)
	if !exit.specific || exit.code != exitShutdownFailure {
		t.Fatalf("shutdown cleanup failure returned specific=%t code=%d", exit.specific, exit.code)
	}
}

func TestStartupInputsAreFixedAndStrict(t *testing.T) {
	if err := validateStartupInputs(`C:\ProgramData\AgentWorkstationGateway`, testSourceSHA); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		root string
		sha  string
		rule string
	}{
		{root: `relative\AWG`, sha: testSourceSHA, rule: "installation-root-invalid"},
		{root: `C:\ProgramData\AgentWorkstationGateway`, sha: "main", rule: "gateway-source-sha-invalid"},
		{root: `C:\ProgramData\AgentWorkstationGateway`, sha: "0123456789ABCDEF0123456789ABCDEF01234567", rule: "gateway-source-sha-invalid"},
	} {
		assertServiceRule(t, validateStartupInputs(test.root, test.sha), test.rule)
	}
}

func TestLocalSystemSIDValidationRejectsOtherIdentity(t *testing.T) {
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal("could not create synthetic non-system SID")
	}
	assertServiceRule(t, validateLocalSystemSID(administrators), "local-system-identity-required")
	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal("could not create LocalSystem SID")
	}
	if err := validateLocalSystemSID(localSystem); err != nil {
		t.Fatal(err)
	}
}

func TestCurrentProcessIdentityValidationUsesNativeTokenUser(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatal("could not query current native TokenUser")
	}
	err = validateLocalSystemIdentity()
	localSystem, createErr := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if createErr != nil {
		t.Fatal("could not create LocalSystem SID")
	}
	if user.User.Sid.Equals(localSystem) {
		if err != nil {
			t.Fatal("LocalSystem token was rejected")
		}
		return
	}
	assertServiceRule(t, err, "local-system-identity-required")
}

func TestRunRejectsInteractiveExecutionWithoutBrokerStartup(t *testing.T) {
	isService, err := svc.IsWindowsService()
	if err != nil {
		t.Fatal("could not query Windows service context")
	}
	if isService {
		t.Skip("test process is running as a Windows service")
	}
	assertServiceRule(t, Run(`C:\ProgramData\AgentWorkstationGateway`, testSourceSHA), "scm-context-required")
}

func TestServeRejectsMissingLifecycleDependencies(t *testing.T) {
	assertServiceRule(t, serve(context.Background(), nil, func(error) bool { return false }), "runtime-loop-invalid")
}

type serviceExit struct {
	specific bool
	code     uint32
}

func validHandler(runtime brokerRuntime, recoverable func(error) bool) *serviceHandler {
	return &serviceHandler{
		installationRoot: `C:\ProgramData\AgentWorkstationGateway`, gatewaySourceSHA: testSourceSHA,
		newRuntime: func(string, string) (brokerRuntime, error) { return runtime, nil }, recoverable: recoverable,
	}
}

func executeAsync(
	handler *serviceHandler,
	requests <-chan svc.ChangeRequest,
	statuses chan<- svc.Status,
) <-chan serviceExit {
	result := make(chan serviceExit, 1)
	go func() {
		specific, code := handler.Execute([]string{Name}, requests, statuses)
		result <- serviceExit{specific: specific, code: code}
	}()
	return result
}

func readStatus(t *testing.T, statuses <-chan svc.Status) svc.Status {
	t.Helper()
	select {
	case status := <-statuses:
		return status
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for service status")
		return svc.Status{}
	}
}

func readExit(t *testing.T, result <-chan serviceExit) serviceExit {
	t.Helper()
	select {
	case exit := <-result:
		return exit
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for service exit")
		return serviceExit{}
	}
}

func assertStatus(t *testing.T, status svc.Status, state svc.State, accepts svc.Accepted) {
	t.Helper()
	if status.State != state || status.Accepts != accepts {
		t.Fatalf("unexpected service status: state=%d accepts=%d", status.State, status.Accepts)
	}
	if state == svc.StartPending && (status.CheckPoint == 0 || status.WaitHint == 0) {
		t.Fatal("start-pending status omitted progress bounds")
	}
	if state == svc.StopPending && (status.CheckPoint == 0 || status.WaitHint == 0) {
		t.Fatal("stop-pending status omitted progress bounds")
	}
}

func assertServiceRule(t *testing.T, err error, rule string) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Rule != rule {
		t.Fatalf("expected %s, got %T / %v", rule, err, err)
	}
}

func commandName(command svc.Cmd) string {
	if command == svc.Stop {
		return "stop"
	}
	return "shutdown"
}
