package accountprovision

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
)

type Role string

const (
	RoleControl   Role = "control"
	RoleExecution Role = "execution"
)

type Account struct {
	Name                   string
	Identifier             string
	PrimaryGroupIdentifier string
}

type Native interface {
	AccountExists(name string) (bool, error)
	CreateAccount(name string, password []byte) (Account, bool, error)
	ApplyPolicy(role Role, account Account) error
	DeleteAccount(name string) error
}

type PasswordGenerator interface {
	Generate() ([]byte, error)
}

type Lease struct {
	Binding           installplan.IdentityBinding
	controlPassword   []byte
	executionPassword []byte
	created           []string
	native            Native
	mu                sync.Mutex
	committed         bool
	closed            bool
}

type Error struct {
	Rule string
}

func (failure *Error) Error() string {
	return fmt.Sprintf("Windows account provisioning failed: %s", failure.Rule)
}

func Provision(
	ctx context.Context,
	specification installplan.Spec,
	native Native,
	generator PasswordGenerator,
) (result *Lease, resultErr error) {
	if ctx == nil || native == nil || generator == nil {
		return nil, provisionError("dependency-required")
	}
	if _, err := installplan.Build(specification); err != nil {
		return nil, provisionError("install-plan-invalid")
	}
	for _, account := range []string{specification.ControlAccount, specification.ExecutionAccount} {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		exists, err := native.AccountExists(account)
		if err != nil {
			return nil, provisionError("account-preflight-failed")
		}
		if exists {
			return nil, provisionError("account-already-exists")
		}
	}
	lease := &Lease{native: native}
	failed := true
	defer func() {
		if failed {
			if err := lease.Close(); err != nil {
				result = nil
				resultErr = provisionError("rollback-failed")
			}
		}
	}()

	controlPassword, err := generator.Generate()
	if err != nil || !validGeneratedPassword(controlPassword) {
		zeroBytes(controlPassword)
		return nil, provisionError("control-password-failed")
	}
	lease.controlPassword = controlPassword
	executionPassword, err := generator.Generate()
	if err != nil || !validGeneratedPassword(executionPassword) {
		zeroBytes(executionPassword)
		return nil, provisionError("execution-password-failed")
	}
	lease.executionPassword = executionPassword

	control, controlCreated, err := native.CreateAccount(specification.ControlAccount, lease.controlPassword)
	if controlCreated {
		lease.created = append(lease.created, specification.ControlAccount)
	}
	if err != nil || !strings.EqualFold(control.Name, specification.ControlAccount) {
		return nil, provisionError("control-account-create-failed")
	}
	execution, executionCreated, err := native.CreateAccount(specification.ExecutionAccount, lease.executionPassword)
	if executionCreated {
		lease.created = append(lease.created, specification.ExecutionAccount)
	}
	if err != nil || !strings.EqualFold(execution.Name, specification.ExecutionAccount) {
		return nil, provisionError("execution-account-create-failed")
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := native.ApplyPolicy(RoleControl, control); err != nil {
		return nil, provisionError("control-account-policy-failed")
	}
	if err := native.ApplyPolicy(RoleExecution, execution); err != nil {
		return nil, provisionError("execution-account-policy-failed")
	}
	binding := installplan.IdentityBinding{
		ControlIdentifier: control.Identifier, ControlPrimaryGroupIdentifier: control.PrimaryGroupIdentifier,
		ExecutionIdentifier: execution.Identifier, ExecutionPrimaryGroupIdentifier: execution.PrimaryGroupIdentifier,
	}
	if _, err := installplan.Bind(specification, binding); err != nil {
		return nil, provisionError("resolved-identity-invalid")
	}
	lease.Binding = binding
	failed = false
	return lease, nil
}

func validGeneratedPassword(password []byte) bool {
	if len(password) == 0 || len(password) > 256 || !utf8.Valid(password) {
		return false
	}
	for _, value := range password {
		if value == 0 {
			return false
		}
	}
	return true
}

func (lease *Lease) ControlPassword() []byte {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return nil
	}
	return lease.controlPassword
}

func (lease *Lease) ExecutionPassword() []byte {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return nil
	}
	return lease.executionPassword
}

func (lease *Lease) Commit() error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return provisionError("lease-closed")
	}
	lease.committed = true
	lease.clearPasswords()
	return nil
}

func (lease *Lease) Close() error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return nil
	}
	lease.closed = true
	lease.clearPasswords()
	if lease.committed {
		return nil
	}
	rollbackFailed := false
	for index := len(lease.created) - 1; index >= 0; index-- {
		if err := lease.native.DeleteAccount(lease.created[index]); err != nil {
			rollbackFailed = true
		}
	}
	if rollbackFailed {
		return provisionError("rollback-failed")
	}
	return nil
}

func (lease *Lease) clearPasswords() {
	zeroBytes(lease.controlPassword)
	zeroBytes(lease.executionPassword)
	lease.controlPassword = nil
	lease.executionPassword = nil
}

func contextError(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return provisionError("context-cancelled")
	default:
		return nil
	}
}

func provisionError(rule string) error {
	return &Error{Rule: rule}
}
