package runnerregistration

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

var (
	registrationToken = []byte("registration-token-synthetic-1")
	removalToken      = []byte("removal-token-synthetic-2")
)

type fakeExecutor struct {
	exits       []int
	errors      []error
	notStarted  map[int]bool
	invocations []Invocation
	tokens      [][]byte
	deadlines   []time.Duration
}

func (executor *fakeExecutor) Run(ctx context.Context, invocation Invocation, token []byte) (ProcessResult, error) {
	executor.invocations = append(executor.invocations, cloneInvocation(invocation))
	executor.tokens = append(executor.tokens, token)
	deadline, ok := ctx.Deadline()
	if !ok {
		executor.deadlines = append(executor.deadlines, 0)
	} else {
		executor.deadlines = append(executor.deadlines, time.Until(deadline))
	}
	index := len(executor.invocations) - 1
	exitCode := 0
	if index < len(executor.exits) {
		exitCode = executor.exits[index]
	}
	var err error
	if index < len(executor.errors) {
		err = executor.errors[index]
	}
	return ProcessResult{Started: !executor.notStarted[index], ExitCode: exitCode}, err
}

type fakeState struct {
	sealCalls   int
	verifyCalls int
	sealErrs    []error
	verifyErr   error
}

func (state *fakeState) SealGeneratedState(context.Context) error {
	index := state.sealCalls
	state.sealCalls++
	if index < len(state.sealErrs) {
		return state.sealErrs[index]
	}
	return nil
}

func (state *fakeState) VerifyRegistrationState(context.Context) error {
	state.verifyCalls++
	return state.verifyErr
}

func TestPrivateRepositoryReceiptRejectsPublicOrAmbiguousTargets(t *testing.T) {
	accepted, err := VerifyPrivateRepository("example/control-plane", true)
	if err != nil || accepted.Name() != "example/control-plane" {
		t.Fatalf("valid private repository rejected: %v", err)
	}
	for _, test := range []struct {
		name       string
		repository string
		private    bool
	}{
		{name: "public", repository: "example/control-plane"},
		{name: "missing owner", repository: "control-plane", private: true},
		{name: "url", repository: "https://github.com/example/control-plane", private: true},
		{name: "git suffix", repository: "example/control-plane.GIT", private: true},
		{name: "trailing dot", repository: "example/control-plane.", private: true},
		{name: "owner alias", repository: "-example/control-plane", private: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := VerifyPrivateRepository(test.repository, test.private); err == nil {
				t.Fatal("unverified repository target was accepted")
			}
		})
	}
}

func TestProvisionRunsOnlyFixedConfigureAndRollbackCommands(t *testing.T) {
	executor := &fakeExecutor{}
	state := &fakeState{}
	lease, err := Provision(context.Background(), `C:\ProgramData\AgentWorkstationGateway`, validRequest(t), executor, state)
	if err != nil {
		t.Fatal(err)
	}
	if len(executor.invocations) != 1 || state.sealCalls != 1 || state.verifyCalls != 1 {
		t.Fatal("registration did not run the configure/seal/verify sequence exactly once")
	}
	configure := executor.invocations[0]
	expectedArguments := []string{
		"configure", "--unattended", "--url", "https://github.com/example/control-plane",
		"--name", "workstation-1", "--work", `C:\ProgramData\AgentWorkstationGateway-runner\_work`,
		"--disableupdate", "--no-default-labels", "--labels", RegistrationLabel,
	}
	if configure.Executable != `C:\ProgramData\AgentWorkstationGateway-runner\bin\Runner.Listener.exe` ||
		configure.WorkingDirectory != `C:\ProgramData\AgentWorkstationGateway-runner` ||
		configure.TokenEnvironment != TokenEnvironment || !reflect.DeepEqual(configure.Arguments, expectedArguments) {
		t.Fatalf("unexpected configure invocation: %#v", configure)
	}
	configureToken := executor.tokens[0]
	assertZeroed(t, configureToken)
	if executor.deadlines[0] <= 0 || executor.deadlines[0] > configureTimeout {
		t.Fatal("configure process was not bounded")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if len(executor.invocations) != 2 || !reflect.DeepEqual(executor.invocations[1].Arguments, []string{"remove"}) ||
		executor.invocations[1].TokenEnvironment != TokenEnvironment || state.sealCalls != 2 {
		t.Fatal("rollback did not attempt fixed remote removal and reseal local state")
	}
	if !bytes.Equal(executor.tokens[1], make([]byte, len(removalToken))) {
		t.Fatal("removal token was not cleared after rollback")
	}
	if executor.deadlines[1] <= 0 || executor.deadlines[1] > cleanupTimeout {
		t.Fatal("remove process was not independently bounded")
	}
}

func TestCommitSuppressesRemoteRemovalAndClearsToken(t *testing.T) {
	executor := &fakeExecutor{}
	lease, err := Provision(context.Background(), `C:\ProgramData\AgentWorkstationGateway`, validRequest(t), executor, &fakeState{})
	if err != nil {
		t.Fatal(err)
	}
	retainedRemoval := lease.removalToken
	if err := lease.Commit(); err != nil {
		t.Fatal(err)
	}
	assertZeroed(t, retainedRemoval)
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if len(executor.invocations) != 1 {
		t.Fatal("committed registration was remotely removed")
	}
}

func TestEveryPostLaunchFailureAttemptsIndependentRemoteCleanup(t *testing.T) {
	tests := []struct {
		name      string
		executor  *fakeExecutor
		state     *fakeState
		cancelled bool
		rule      string
	}{
		{name: "process error after start", executor: &fakeExecutor{errors: []error{errors.New("synthetic")}}, state: &fakeState{}, rule: "configure-process-failed"},
		{name: "process exit", executor: &fakeExecutor{exits: []int{17}}, state: &fakeState{}, rule: "configure-process-failed"},
		{name: "seal", executor: &fakeExecutor{}, state: &fakeState{sealErrs: []error{errors.New("synthetic")}}, rule: "generated-state-seal-failed"},
		{name: "verify", executor: &fakeExecutor{}, state: &fakeState{verifyErr: errors.New("synthetic")}, rule: "registration-state-invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lease, err := Provision(context.Background(), `C:\ProgramData\AgentWorkstationGateway`, validRequest(t), test.executor, test.state)
			if lease != nil {
				t.Fatal("failed registration produced a lease")
			}
			assertRule(t, err, test.rule)
			if len(test.executor.invocations) != 2 || !reflect.DeepEqual(test.executor.invocations[1].Arguments, []string{"remove"}) {
				t.Fatal("post-launch failure did not attempt remote cleanup")
			}
		})
	}
}

func TestPreLaunchExecutorFailureDoesNotAttemptRemoteRemoval(t *testing.T) {
	executor := &fakeExecutor{errors: []error{errors.New("synthetic pre-launch failure")}, notStarted: map[int]bool{0: true}}
	lease, err := Provision(context.Background(), `C:\ProgramData\AgentWorkstationGateway`, validRequest(t), executor, &fakeState{})
	if lease != nil {
		t.Fatal("pre-launch failure produced a lease")
	}
	assertRule(t, err, "configure-process-failed")
	if len(executor.invocations) != 1 {
		t.Fatal("pre-launch failure attempted an impossible remote cleanup")
	}
}

func TestRollbackFailureIsNotHidden(t *testing.T) {
	executor := &fakeExecutor{exits: []int{9, 8}}
	lease, err := Provision(context.Background(), `C:\ProgramData\AgentWorkstationGateway`, validRequest(t), executor, &fakeState{})
	if lease != nil {
		t.Fatal("rollback failure produced a lease")
	}
	assertRule(t, err, "registration-rollback-failed")
}

func TestPreflightRejectsCredentialsAndDependenciesBeforeLaunch(t *testing.T) {
	repository, err := VerifyPrivateRepository("example/control-plane", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		request Request
	}{
		{name: "zero receipt", request: Request{RunnerName: "workstation-1", RegistrationToken: registrationToken, RemovalToken: removalToken}},
		{name: "runner name", request: Request{Repository: repository, RunnerName: "unsafe name", RegistrationToken: registrationToken, RemovalToken: removalToken}},
		{name: "registration token", request: Request{Repository: repository, RunnerName: "workstation-1", RegistrationToken: []byte("short"), RemovalToken: removalToken}},
		{name: "removal token", request: Request{Repository: repository, RunnerName: "workstation-1", RegistrationToken: registrationToken, RemovalToken: []byte("line\nbreak-token-value")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			executor := &fakeExecutor{}
			if lease, err := Provision(context.Background(), `C:\ProgramData\AgentWorkstationGateway`, test.request, executor, &fakeState{}); lease != nil || err == nil {
				t.Fatal("invalid registration input was accepted")
			}
			if len(executor.invocations) != 0 {
				t.Fatal("invalid registration input launched a process")
			}
		})
	}
	executor := &fakeExecutor{}
	if lease, err := Provision(context.Background(), `C:\ProgramData\AgentWorkstationGateway`, validRequest(t), executor, nil); lease != nil || err == nil {
		t.Fatal("missing state dependency was accepted")
	}
	if len(executor.invocations) != 0 {
		t.Fatal("missing dependency launched a process")
	}
}

func TestPreparePinsCredentialCopies(t *testing.T) {
	request := validRequest(t)
	prepared, err := prepare(`C:\ProgramData\AgentWorkstationGateway`, request)
	if err != nil {
		t.Fatal(err)
	}
	request.RegistrationToken[0] = 'x'
	request.RemovalToken[0] = 'y'
	if prepared.registrationToken[0] == 'x' || prepared.removalToken[0] == 'y' {
		t.Fatal("prepared credential material aliased caller buffers")
	}
	zeroBytes(prepared.registrationToken)
	zeroBytes(prepared.removalToken)
}

func validRequest(t *testing.T) Request {
	t.Helper()
	repository, err := VerifyPrivateRepository("example/control-plane", true)
	if err != nil {
		t.Fatal(err)
	}
	return Request{
		Repository: repository, RunnerName: "workstation-1",
		RegistrationToken: append([]byte(nil), registrationToken...),
		RemovalToken:      append([]byte(nil), removalToken...),
	}
}

func cloneInvocation(invocation Invocation) Invocation {
	invocation.Arguments = append([]string(nil), invocation.Arguments...)
	return invocation
}

func assertRule(t *testing.T, err error, rule string) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Rule != rule {
		t.Fatalf("expected %s, got %T / %v", rule, err, err)
	}
}

func assertZeroed(t *testing.T, buffer []byte) {
	t.Helper()
	for _, value := range buffer {
		if value != 0 {
			t.Fatal("credential buffer was not cleared")
		}
	}
}
