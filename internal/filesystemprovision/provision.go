package filesystemprovision

import (
	"context"
	"fmt"
	"sync"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

type Change interface {
	Rollback() error
	Discard()
}

type Native interface {
	ConvergeApprovedRoot(path string, executionIdentifier string) (Change, error)
	ConvergeIsolatedRoot(path string, executionIdentifier string) (Change, error)
}

type Lease struct {
	changes   []Change
	mu        sync.Mutex
	committed bool
	closed    bool
}

type Error struct {
	Rule string
}

func (failure *Error) Error() string {
	return fmt.Sprintf("Windows filesystem provisioning failed: %s", failure.Rule)
}

func Provision(ctx context.Context, configuration installconfig.Config, native Native) (result *Lease, resultErr error) {
	if ctx == nil || native == nil {
		return nil, provisionError("dependency-required")
	}
	if configuration.Platform != platformpath.Windows || installconfig.Validate(configuration) != nil {
		return nil, provisionError("installed-configuration-invalid")
	}
	lease := &Lease{}
	failed := true
	defer func() {
		if failed {
			if err := lease.Close(); err != nil {
				result = nil
				resultErr = provisionError("rollback-failed")
			}
		}
	}()
	for _, root := range configuration.ApprovedRoots {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		change, err := native.ConvergeApprovedRoot(root, configuration.ExecutionIdentity.Identifier)
		if err != nil || change == nil {
			return nil, provisionError("approved-root-convergence-failed")
		}
		lease.changes = append(lease.changes, change)
	}
	for _, root := range []string{configuration.ProfileRoot, configuration.TempRoot} {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		change, err := native.ConvergeIsolatedRoot(root, configuration.ExecutionIdentity.Identifier)
		if err != nil || change == nil {
			return nil, provisionError("isolated-root-convergence-failed")
		}
		lease.changes = append(lease.changes, change)
	}
	failed = false
	return lease, nil
}

func (lease *Lease) Commit() error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return provisionError("lease-closed")
	}
	lease.committed = true
	for _, change := range lease.changes {
		change.Discard()
	}
	lease.changes = nil
	return nil
}

func (lease *Lease) Close() error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return nil
	}
	lease.closed = true
	if lease.committed {
		return nil
	}
	rollbackFailed := false
	for index := len(lease.changes) - 1; index >= 0; index-- {
		if err := lease.changes[index].Rollback(); err != nil {
			rollbackFailed = true
		}
		lease.changes[index].Discard()
	}
	lease.changes = nil
	if rollbackFailed {
		return provisionError("rollback-failed")
	}
	return nil
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
