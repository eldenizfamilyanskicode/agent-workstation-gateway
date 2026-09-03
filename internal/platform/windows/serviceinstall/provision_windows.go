//go:build windows

package serviceinstall

import (
	"context"
	"sync"
)

type nativeBackend interface {
	BinaryReady(string, int) error
	ServiceExists(string) (bool, error)
	Create(Plan) (managedService, bool, error)
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

func Provision(ctx context.Context, installationRoot string) (*Lease, error) {
	if ctx == nil {
		return nil, installError("dependency-required")
	}
	if _, err := BuildPlan(installationRoot); err != nil {
		return nil, err
	}
	native, err := newNativeBackend()
	if err != nil {
		return nil, installError("scm-connect-failed")
	}
	return provisionWithNative(ctx, installationRoot, native)
}

func provisionWithNative(ctx context.Context, installationRoot string, native nativeBackend) (*Lease, error) {
	if native == nil {
		return nil, installError("dependency-required")
	}
	lease, provisionErr := provision(ctx, installationRoot, native)
	closeErr := native.Close()
	if provisionErr != nil {
		return nil, provisionErr
	}
	if closeErr != nil {
		if err := lease.Close(); err != nil {
			return nil, err
		}
		return nil, installError("scm-close-failed")
	}
	return lease, nil
}

func provision(ctx context.Context, installationRoot string, native nativeBackend) (result *Lease, resultErr error) {
	if ctx == nil || native == nil {
		return nil, installError("dependency-required")
	}
	plan, err := BuildPlan(installationRoot)
	if err != nil {
		return nil, err
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := native.BinaryReady(plan.Executable, maxBrokerBytes); err != nil {
		return nil, installError("broker-binary-invalid")
	}
	exists, err := native.ServiceExists(plan.Name)
	if err != nil {
		return nil, installError("service-preflight-failed")
	}
	if exists {
		return nil, installError("service-already-exists")
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	service, created, err := native.Create(plan)
	lease := &Lease{}
	if created {
		lease.service = service
	}
	failed := true
	defer func() {
		if failed && lease.service != nil {
			if rollbackErr := lease.Close(); rollbackErr != nil {
				result = nil
				resultErr = installError("service-rollback-failed")
			}
		}
	}()
	if err != nil || !created || service == nil {
		return nil, installError("service-create-failed")
	}
	if err := service.Apply(plan); err != nil {
		return nil, installError("service-policy-apply-failed")
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := service.Verify(plan); err != nil {
		return nil, installError("service-policy-verification-failed")
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	failed = false
	return lease, nil
}

func (lease *Lease) Commit() error {
	if lease == nil {
		return installError("lease-invalid")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed || lease.service == nil {
		return installError("lease-closed")
	}
	lease.committed = true
	if err := lease.service.Close(); err != nil {
		return installError("service-handle-close-failed")
	}
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
		return installError("service-rollback-failed")
	}
	return nil
}

func contextError(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return installError("context-cancelled")
	default:
		return nil
	}
}
