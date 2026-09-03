//go:build windows

package runnerservice

import (
	"context"
	"sync"
	"unicode/utf8"
)

type RunnerFiles interface {
	VerifyServiceExecutable(context.Context) error
}

type nativeBackend interface {
	ServiceExists(string) (bool, error)
	Create(Plan, []byte) (managedService, bool, error)
	Close() error
}

type managedService interface {
	Apply(Plan) error
	Verify(Plan) error
	Delete() error
	Close() error
}

type Lease struct {
	service   managedService
	mu        sync.Mutex
	committed bool
	closed    bool
}

func Provision(
	ctx context.Context,
	installationRoot string,
	controlAccount string,
	controlPassword []byte,
	files RunnerFiles,
) (*Lease, error) {
	if ctx == nil || files == nil || !validPassword(controlPassword) {
		return nil, serviceError("dependency-required")
	}
	if _, err := BuildPlan(installationRoot, controlAccount); err != nil {
		return nil, err
	}
	native, err := newNativeBackend()
	if err != nil {
		return nil, serviceError("scm-connect-failed")
	}
	return provisionWithNative(ctx, installationRoot, controlAccount, controlPassword, files, native)
}

func provisionWithNative(
	ctx context.Context,
	installationRoot string,
	controlAccount string,
	controlPassword []byte,
	files RunnerFiles,
	native nativeBackend,
) (*Lease, error) {
	if native == nil {
		return nil, serviceError("dependency-required")
	}
	lease, provisionErr := provision(ctx, installationRoot, controlAccount, controlPassword, files, native)
	closeErr := native.Close()
	if provisionErr != nil {
		return nil, provisionErr
	}
	if closeErr != nil {
		if err := lease.Close(); err != nil {
			return nil, err
		}
		return nil, serviceError("scm-close-failed")
	}
	return lease, nil
}

func provision(
	ctx context.Context,
	installationRoot string,
	controlAccount string,
	controlPassword []byte,
	files RunnerFiles,
	native nativeBackend,
) (result *Lease, resultErr error) {
	if ctx == nil || files == nil || native == nil || !validPassword(controlPassword) {
		return nil, serviceError("dependency-required")
	}
	plan, err := BuildPlan(installationRoot, controlAccount)
	if err != nil {
		return nil, err
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := files.VerifyServiceExecutable(ctx); err != nil {
		return nil, serviceError("runner-service-image-invalid")
	}
	exists, err := native.ServiceExists(plan.Name)
	if err != nil {
		return nil, serviceError("service-preflight-failed")
	}
	if exists {
		return nil, serviceError("service-already-exists")
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	service, created, err := native.Create(plan, controlPassword)
	lease := &Lease{}
	if created {
		lease.service = service
	}
	failed := true
	defer func() {
		if failed && lease.service != nil {
			if rollbackErr := lease.Close(); rollbackErr != nil {
				result = nil
				resultErr = serviceError("service-rollback-failed")
			}
		}
	}()
	if err != nil || !created || service == nil {
		return nil, serviceError("service-create-failed")
	}
	if err := service.Apply(plan); err != nil {
		return nil, serviceError("service-policy-apply-failed")
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := service.Verify(plan); err != nil {
		return nil, serviceError("service-policy-verification-failed")
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	failed = false
	return lease, nil
}

func (lease *Lease) Commit() error {
	if lease == nil {
		return serviceError("lease-invalid")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed || lease.service == nil {
		return serviceError("lease-closed")
	}
	if err := lease.service.Close(); err != nil {
		return serviceError("service-handle-close-failed")
	}
	lease.committed = true
	lease.closed = true
	lease.service = nil
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
	if lease.service == nil {
		return nil
	}
	failed := false
	if !lease.committed && lease.service.Delete() != nil {
		failed = true
	}
	if lease.service.Close() != nil {
		failed = true
	}
	lease.service = nil
	if failed {
		return serviceError("service-rollback-failed")
	}
	return nil
}

func contextError(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return serviceError("context-cancelled")
	default:
		return nil
	}
}

func validPassword(password []byte) bool {
	if len(password) == 0 || len(password) > 1024 || !utf8.Valid(password) {
		return false
	}
	for _, value := range password {
		if value == 0 {
			return false
		}
	}
	return true
}
