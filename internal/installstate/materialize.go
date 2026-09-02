package installstate

import (
	"context"
	"fmt"
	"runtime"
	"unicode/utf8"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
)

const MaxPasswordBytes = 1024

type Store interface {
	EnsureProtectedDirectory(path string) error
	WriteProtectedFile(path string, content []byte) error
}

type Sealer interface {
	Seal(password []byte) ([]byte, error)
}

type Receipt struct {
	Layout            installplan.Layout
	CredentialWritten bool
	ConfigWritten     bool
}

type Error struct {
	Rule string
}

func (failure *Error) Error() string {
	return fmt.Sprintf("installation state materialization failed: %s", failure.Rule)
}

func Materialize(
	ctx context.Context,
	specification installplan.Spec,
	binding installplan.IdentityBinding,
	password []byte,
	store Store,
	sealer Sealer,
) (Receipt, error) {
	if ctx == nil || store == nil || sealer == nil {
		return Receipt{}, stateError("dependency-required")
	}
	plan, err := installplan.Build(specification)
	if err != nil {
		return Receipt{}, stateError("install-plan-invalid")
	}
	configuration, err := installplan.Bind(specification, binding)
	if err != nil {
		return Receipt{}, stateError("identity-binding-invalid")
	}
	canonicalConfig, err := installconfig.MarshalCanonical(configuration)
	if err != nil {
		return Receipt{}, stateError("configuration-encode-failed")
	}
	if !validPassword(password) {
		return Receipt{}, stateError("password-invalid")
	}
	plaintext := append([]byte(nil), password...)
	defer zeroBytes(plaintext)

	for _, directory := range []string{plan.Layout.Root, plan.Layout.BinDirectory, plan.Layout.StateDirectory} {
		if err := contextError(ctx); err != nil {
			return Receipt{}, err
		}
		if err := store.EnsureProtectedDirectory(directory); err != nil {
			return Receipt{}, stateError("protected-directory-failed")
		}
	}
	if err := contextError(ctx); err != nil {
		return Receipt{}, err
	}
	protected, err := sealer.Seal(plaintext)
	zeroBytes(plaintext)
	if err != nil || len(protected) == 0 {
		zeroBytes(protected)
		return Receipt{}, stateError("credential-seal-failed")
	}
	defer zeroBytes(protected)
	if err := store.WriteProtectedFile(plan.Layout.ExecutionCredential, protected); err != nil {
		return Receipt{}, stateError("credential-write-failed")
	}
	if err := contextError(ctx); err != nil {
		return Receipt{Layout: plan.Layout, CredentialWritten: true}, err
	}
	if err := store.WriteProtectedFile(plan.Layout.InstallationConfig, canonicalConfig); err != nil {
		return Receipt{Layout: plan.Layout, CredentialWritten: true}, stateError("configuration-write-failed")
	}
	return Receipt{Layout: plan.Layout, CredentialWritten: true, ConfigWritten: true}, nil
}

func validPassword(password []byte) bool {
	if len(password) == 0 || len(password) > MaxPasswordBytes || !utf8.Valid(password) {
		return false
	}
	for _, value := range password {
		if value == 0 {
			return false
		}
	}
	return true
}

func contextError(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return stateError("context-cancelled")
	default:
		return nil
	}
}

func stateError(rule string) error {
	return &Error{Rule: rule}
}

//go:noinline
func zeroBytes(buffer []byte) {
	for index := range buffer {
		buffer[index] = 0
	}
	runtime.KeepAlive(buffer)
}
