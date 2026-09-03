package runnerregistration

import (
	"context"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

const (
	MaxRepositoryBytes = 201
	MaxRunnerNameBytes = 64
	MaxTokenBytes      = 1024
	MinTokenBytes      = 16
	RegistrationLabel  = "agent-workstation-gateway"
	TokenEnvironment   = "ACTIONS_RUNNER_INPUT_TOKEN"
	configureTimeout   = 5 * time.Minute
	cleanupTimeout     = 2 * time.Minute
	localSealTimeout   = 30 * time.Second
)

var (
	ownerPattern      = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
	runnerNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

type PrivateRepository struct {
	name string
	url  string
}

type Request struct {
	Repository        PrivateRepository
	RunnerName        string
	RegistrationToken []byte
	RemovalToken      []byte
}

type Invocation struct {
	Executable       string
	WorkingDirectory string
	Arguments        []string
	TokenEnvironment string
}

type Executor interface {
	Run(context.Context, Invocation, []byte) (ProcessResult, error)
}

type ProcessResult struct {
	Started  bool
	ExitCode int
}

type State interface {
	SealGeneratedState(context.Context) error
	VerifyRegistrationState(context.Context) error
}

type Lease struct {
	mu              sync.Mutex
	executor        Executor
	state           State
	remove          Invocation
	removalToken    []byte
	cleanupRequired bool
	committed       bool
	closed          bool
}

type preparedRequest struct {
	configure         Invocation
	remove            Invocation
	registrationToken []byte
	removalToken      []byte
}

type Error struct {
	Rule string
}

func (failure *Error) Error() string {
	return fmt.Sprintf("runner registration failed: %s", failure.Rule)
}

// VerifyPrivateRepository creates the opaque receipt required by the runner
// transaction only after a trusted caller has established private visibility.
func VerifyPrivateRepository(repository string, private bool) (PrivateRepository, error) {
	if !private || len(repository) == 0 || len(repository) > MaxRepositoryBytes ||
		strings.Count(repository, "/") != 1 {
		return PrivateRepository{}, registrationError("private-repository-required")
	}
	parts := strings.Split(repository, "/")
	if !ownerPattern.MatchString(parts[0]) || !repositoryPattern.MatchString(parts[1]) ||
		parts[1] == "." || parts[1] == ".." || strings.HasSuffix(parts[1], ".") ||
		strings.HasSuffix(strings.ToLower(parts[1]), ".git") {
		return PrivateRepository{}, registrationError("repository-invalid")
	}
	return PrivateRepository{name: repository, url: "https://github.com/" + repository}, nil
}

func (repository PrivateRepository) Name() string { return repository.name }

func ValidateRequest(installationRoot string, request Request) error {
	prepared, err := prepare(installationRoot, request)
	if err != nil {
		return err
	}
	zeroBytes(prepared.registrationToken)
	zeroBytes(prepared.removalToken)
	return nil
}

func Provision(
	ctx context.Context,
	installationRoot string,
	request Request,
	executor Executor,
	state State,
) (result *Lease, resultErr error) {
	prepared, err := prepare(installationRoot, request)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(prepared.registrationToken)
	failed := true
	lease := &Lease{
		executor: executor, state: state, remove: prepared.remove,
		removalToken: prepared.removalToken,
	}
	defer func() {
		if failed {
			if rollbackErr := lease.Close(); rollbackErr != nil {
				result = nil
				resultErr = registrationError("registration-rollback-failed")
			}
		}
	}()
	if ctx == nil || executor == nil || state == nil {
		return nil, registrationError("dependency-required")
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	configureContext, cancel := context.WithTimeout(ctx, configureTimeout)
	processResult, runErr := executor.Run(configureContext, prepared.configure, prepared.registrationToken)
	lease.cleanupRequired = processResult.Started
	cancel()
	sealContext, sealCancel := context.WithTimeout(context.Background(), localSealTimeout)
	sealErr := state.SealGeneratedState(sealContext)
	sealCancel()
	if sealErr != nil {
		return nil, registrationError("generated-state-seal-failed")
	}
	if runErr != nil || !processResult.Started || processResult.ExitCode != 0 {
		return nil, registrationError("configure-process-failed")
	}
	if err := state.VerifyRegistrationState(ctx); err != nil {
		return nil, registrationError("registration-state-invalid")
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	failed = false
	return lease, nil
}

func prepare(installationRoot string, request Request) (preparedRequest, error) {
	layout, err := installplan.WindowsLayout(installationRoot)
	if err != nil {
		return preparedRequest{}, registrationError("installation-root-invalid")
	}
	if request.Repository.name == "" || request.Repository.url == "" ||
		request.Repository.url != "https://github.com/"+request.Repository.name {
		return preparedRequest{}, registrationError("private-repository-required")
	}
	if !runnerNamePattern.MatchString(request.RunnerName) || request.RunnerName == "." || request.RunnerName == ".." {
		return preparedRequest{}, registrationError("runner-name-invalid")
	}
	if !validToken(request.RegistrationToken) || !validToken(request.RemovalToken) {
		return preparedRequest{}, registrationError("token-invalid")
	}
	listener := layout.RunnerRoot + `\bin\Runner.Listener.exe`
	if platformpath.ValidateAbsolute(platformpath.Windows, listener) != nil ||
		!platformpath.Contains(platformpath.Windows, layout.RunnerRoot, listener) {
		return preparedRequest{}, registrationError("listener-path-invalid")
	}
	configure := Invocation{
		Executable: listener, WorkingDirectory: layout.RunnerRoot, TokenEnvironment: TokenEnvironment,
		Arguments: []string{
			"configure", "--unattended", "--url", request.Repository.url,
			"--name", request.RunnerName, "--work", layout.RunnerWorkDirectory,
			"--disableupdate", "--no-default-labels", "--labels", RegistrationLabel,
		},
	}
	remove := Invocation{
		Executable: listener, WorkingDirectory: layout.RunnerRoot,
		Arguments: []string{"remove"}, TokenEnvironment: TokenEnvironment,
	}
	return preparedRequest{
		configure: configure, remove: remove,
		registrationToken: append([]byte(nil), request.RegistrationToken...),
		removalToken:      append([]byte(nil), request.RemovalToken...),
	}, nil
}

func (lease *Lease) Commit() error {
	if lease == nil {
		return registrationError("lease-invalid")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed || lease.executor == nil || lease.state == nil || len(lease.removalToken) == 0 {
		return registrationError("lease-closed")
	}
	lease.committed = true
	lease.closed = true
	lease.executor = nil
	lease.state = nil
	zeroBytes(lease.removalToken)
	lease.removalToken = nil
	return nil
}

func (lease *Lease) Close() error {
	if lease == nil {
		return nil
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return nil
	}
	lease.closed = true
	if lease.committed {
		return nil
	}
	failed := false
	if !lease.cleanupRequired {
		// No configuration process ran, so no remote registration boundary
		// could have been crossed.
	} else if lease.executor == nil || lease.state == nil || len(lease.removalToken) == 0 {
		failed = true
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		processResult, err := lease.executor.Run(ctx, lease.remove, lease.removalToken)
		cancel()
		if err != nil || !processResult.Started || processResult.ExitCode != 0 {
			failed = true
		}
		sealContext, sealCancel := context.WithTimeout(context.Background(), localSealTimeout)
		sealErr := lease.state.SealGeneratedState(sealContext)
		sealCancel()
		if sealErr != nil {
			failed = true
		}
	}
	lease.executor = nil
	lease.state = nil
	zeroBytes(lease.removalToken)
	lease.removalToken = nil
	if failed {
		return registrationError("remote-cleanup-failed")
	}
	return nil
}

func validToken(token []byte) bool {
	if len(token) < MinTokenBytes || len(token) > MaxTokenBytes {
		return false
	}
	for _, value := range token {
		if value < 0x21 || value > 0x7e {
			return false
		}
	}
	return true
}

func contextError(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return registrationError("context-cancelled")
	default:
		return nil
	}
}

//go:noinline
func zeroBytes(buffer []byte) {
	for index := range buffer {
		buffer[index] = 0
	}
	runtime.KeepAlive(buffer)
}

func registrationError(rule string) error { return &Error{Rule: rule} }
