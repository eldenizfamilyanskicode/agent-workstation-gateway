//go:build windows

package installer

import (
	"context"
	"runtime"
	"sync"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/accountprovision"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/filesystemprovision"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	sharedstate "github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installstate"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/account"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/filesystem"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/installroot"
	winstate "github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/installstate"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/serviceinstall"
)

type accountTransaction interface {
	IdentityBinding() installplan.IdentityBinding
	ControlPassword() []byte
	ExecutionPassword() []byte
	ClearExecutionPassword() error
	Commit() error
	Close() error
}

type filesystemTransaction interface {
	Commit() error
	Close() error
}

type rootTransaction interface {
	sharedstate.Store
	InstallationLayout() (installplan.Layout, error)
	WriteBrokerImage(context.Context, []byte) error
	Commit() error
	Close() error
}

type serviceTransaction interface {
	Commit() error
	Close() error
}

type dependencies struct {
	preflightService func() error
	accounts         func(context.Context, installplan.Spec) (accountTransaction, error)
	filesystem       func(context.Context, installconfig.Config) (filesystemTransaction, error)
	root             func(context.Context, string) (rootTransaction, error)
	materialize      func(
		context.Context,
		installplan.Spec,
		installplan.IdentityBinding,
		[]byte,
		sharedstate.Store,
	) (sharedstate.Receipt, error)
	service func(context.Context, string) (serviceTransaction, error)
}

type nativeAccountTransaction struct {
	lease *accountprovision.Lease
}

type Lease struct {
	mu            sync.Mutex
	accounts      accountTransaction
	filesystem    filesystemTransaction
	root          rootTransaction
	service       serviceTransaction
	configuration installconfig.Config
	sourceSHA     string
	closed        bool
}

func Provision(ctx context.Context, input Input) (*Lease, error) {
	prepared, err := prepareInput(input)
	if err != nil {
		return nil, err
	}
	return provision(ctx, prepared, nativeDependencies())
}

func provision(
	ctx context.Context,
	prepared preparedInput,
	deps dependencies,
) (result *Lease, resultErr error) {
	if ctx == nil || !completeDependencies(deps) {
		return nil, installerError("dependency-required")
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := deps.preflightService(); err != nil {
		return nil, installerError("service-preflight-failed")
	}
	lease := &Lease{sourceSHA: prepared.gatewaySourceSHA}
	failed := true
	defer func() {
		if failed {
			if rollbackErr := lease.Close(); rollbackErr != nil {
				result = nil
				resultErr = installerError("rollback-failed")
			}
		}
	}()

	accounts, err := deps.accounts(ctx, prepared.specification)
	if err != nil || accounts == nil {
		return nil, installerError("account-provision-failed")
	}
	lease.accounts = accounts
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	binding := accounts.IdentityBinding()
	configuration, err := installplan.Bind(prepared.specification, binding)
	if err != nil {
		return nil, installerError("identity-binding-invalid")
	}
	filesystemLease, err := deps.filesystem(ctx, configuration)
	if err != nil || filesystemLease == nil {
		return nil, installerError("filesystem-provision-failed")
	}
	lease.filesystem = filesystemLease
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	rootLease, err := deps.root(ctx, prepared.specification.InstallationRoot)
	if err != nil || rootLease == nil {
		return nil, installerError("installation-root-provision-failed")
	}
	lease.root = rootLease
	if err := rootLease.WriteBrokerImage(ctx, prepared.brokerImage); err != nil {
		return nil, installerError("broker-image-materialization-failed")
	}
	prepared.brokerImage = nil
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	executionPassword := accounts.ExecutionPassword()
	if len(executionPassword) == 0 {
		return nil, installerError("execution-password-unavailable")
	}
	receipt, err := deps.materialize(
		ctx, prepared.specification, binding, executionPassword, rootLease,
	)
	if err != nil {
		return nil, installerError("installation-state-materialization-failed")
	}
	layout, layoutErr := rootLease.InstallationLayout()
	if layoutErr != nil || receipt.Layout != layout || !receipt.CredentialWritten || !receipt.ConfigWritten {
		return nil, installerError("installation-state-verification-failed")
	}
	if err := accounts.ClearExecutionPassword(); err != nil || accounts.ExecutionPassword() != nil {
		return nil, installerError("execution-password-clear-failed")
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	serviceLease, err := deps.service(ctx, prepared.specification.InstallationRoot)
	if err != nil || serviceLease == nil {
		return nil, installerError("service-provision-failed")
	}
	lease.service = serviceLease
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if len(accounts.ControlPassword()) == 0 {
		return nil, installerError("control-password-unavailable")
	}
	lease.configuration = cloneConfiguration(configuration)
	failed = false
	return lease, nil
}

// UseControlPassword provides a bounded temporary copy for the later trusted
// runner-service installer. The copy is cleared immediately after the
// synchronous consumer returns and is never formatted as a string here.
func (lease *Lease) UseControlPassword(consumer func([]byte) error) error {
	if lease == nil || consumer == nil {
		return installerError("dependency-required")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed || lease.accounts == nil {
		return installerError("lease-closed")
	}
	password := append([]byte(nil), lease.accounts.ControlPassword()...)
	if len(password) == 0 {
		return installerError("control-password-unavailable")
	}
	defer zeroBytes(password)
	if err := consumer(password); err != nil {
		return installerError("control-password-consumer-failed")
	}
	return nil
}

func (lease *Lease) Configuration() (installconfig.Config, error) {
	if lease == nil {
		return installconfig.Config{}, installerError("lease-invalid")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return installconfig.Config{}, installerError("lease-closed")
	}
	return cloneConfiguration(lease.configuration), nil
}

func (lease *Lease) GatewaySourceSHA() (string, error) {
	if lease == nil {
		return "", installerError("lease-invalid")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return "", installerError("lease-closed")
	}
	return lease.sourceSHA, nil
}

func (lease *Lease) Commit() error {
	if lease == nil {
		return installerError("lease-invalid")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed || lease.accounts == nil || lease.filesystem == nil || lease.root == nil || lease.service == nil {
		return installerError("lease-closed")
	}
	if err := lease.service.Commit(); err != nil {
		rollbackFailed := lease.rollbackLocked()
		lease.closed = true
		if rollbackFailed {
			return installerError("commit-rollback-failed")
		}
		return installerError("service-commit-failed")
	}
	lease.service = nil

	finalizationFailed := false
	if lease.accounts.Commit() != nil {
		finalizationFailed = true
	}
	if lease.filesystem.Commit() != nil {
		finalizationFailed = true
	}
	if lease.root.Commit() != nil {
		finalizationFailed = true
	}
	lease.accounts = nil
	lease.filesystem = nil
	lease.root = nil
	lease.closed = true
	lease.configuration = installconfig.Config{}
	lease.sourceSHA = ""
	if finalizationFailed {
		return installerError("commit-finalization-failed")
	}
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
	failed := lease.rollbackLocked()
	lease.configuration = installconfig.Config{}
	lease.sourceSHA = ""
	if failed {
		return installerError("rollback-failed")
	}
	return nil
}

func (lease *Lease) rollbackLocked() bool {
	failed := false
	if lease.service != nil {
		if lease.service.Close() != nil {
			failed = true
		}
		lease.service = nil
	}
	if lease.root != nil {
		if lease.root.Close() != nil {
			failed = true
		}
		lease.root = nil
	}
	if lease.filesystem != nil {
		if lease.filesystem.Close() != nil {
			failed = true
		}
		lease.filesystem = nil
	}
	if lease.accounts != nil {
		if lease.accounts.Close() != nil {
			failed = true
		}
		lease.accounts = nil
	}
	return failed
}

func nativeDependencies() dependencies {
	return dependencies{
		preflightService: func() error {
			exists, err := serviceinstall.ProbeFixedService()
			if err != nil || exists {
				return installerError("fixed-service-unavailable")
			}
			return nil
		},
		accounts: func(ctx context.Context, specification installplan.Spec) (accountTransaction, error) {
			native, err := account.NewNative(specification)
			if err != nil {
				return nil, err
			}
			lease, err := accountprovision.Provision(
				ctx, specification, native, accountprovision.CryptoPasswordGenerator{},
			)
			if err != nil {
				return nil, err
			}
			return &nativeAccountTransaction{lease: lease}, nil
		},
		filesystem: func(ctx context.Context, configuration installconfig.Config) (filesystemTransaction, error) {
			native, err := filesystem.New(configuration)
			if err != nil {
				return nil, err
			}
			return filesystemprovision.Provision(ctx, configuration, native)
		},
		root: func(ctx context.Context, installationRoot string) (rootTransaction, error) {
			return installroot.Provision(ctx, installationRoot)
		},
		materialize: func(
			ctx context.Context,
			specification installplan.Spec,
			binding installplan.IdentityBinding,
			password []byte,
			store sharedstate.Store,
		) (sharedstate.Receipt, error) {
			return sharedstate.Materialize(
				ctx, specification, binding, password, store, winstate.DPAPISealer{},
			)
		},
		service: func(ctx context.Context, installationRoot string) (serviceTransaction, error) {
			return serviceinstall.Provision(ctx, installationRoot)
		},
	}
}

func completeDependencies(deps dependencies) bool {
	return deps.preflightService != nil && deps.accounts != nil && deps.filesystem != nil &&
		deps.root != nil && deps.materialize != nil && deps.service != nil
}

func (transaction *nativeAccountTransaction) IdentityBinding() installplan.IdentityBinding {
	return transaction.lease.Binding
}

func (transaction *nativeAccountTransaction) ControlPassword() []byte {
	return transaction.lease.ControlPassword()
}

func (transaction *nativeAccountTransaction) ExecutionPassword() []byte {
	return transaction.lease.ExecutionPassword()
}

func (transaction *nativeAccountTransaction) ClearExecutionPassword() error {
	return transaction.lease.ClearExecutionPassword()
}

func (transaction *nativeAccountTransaction) Commit() error { return transaction.lease.Commit() }
func (transaction *nativeAccountTransaction) Close() error  { return transaction.lease.Close() }

func cloneConfiguration(configuration installconfig.Config) installconfig.Config {
	configuration.ApprovedRoots = append([]string(nil), configuration.ApprovedRoots...)
	configuration.Shells = append([]installconfig.ShellBinding(nil), configuration.Shells...)
	configuration.PathEntries = append([]string(nil), configuration.PathEntries...)
	configuration.Capabilities = append([]installconfig.Capability(nil), configuration.Capabilities...)
	return configuration
}

func contextError(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return installerError("context-cancelled")
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
