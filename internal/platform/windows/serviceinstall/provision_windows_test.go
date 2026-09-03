//go:build windows

package serviceinstall

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/brokerservice"
)

type fakeBackend struct {
	binaryErr   error
	exists      bool
	existsErr   error
	createErr   error
	created     bool
	service     *fakeManagedService
	binaryPath  string
	binaryMax   int
	existsName  string
	createPlan  Plan
	createCalls int
	closeCalls  int
	closeErr    error
}

func (native *fakeBackend) BinaryReady(path string, maximum int) error {
	native.binaryPath, native.binaryMax = path, maximum
	return native.binaryErr
}

func (native *fakeBackend) ServiceExists(name string) (bool, error) {
	native.existsName = name
	return native.exists, native.existsErr
}

func (native *fakeBackend) Create(plan Plan) (managedService, bool, error) {
	native.createCalls++
	native.createPlan = plan
	return native.service, native.created, native.createErr
}

func (native *fakeBackend) Close() error {
	native.closeCalls++
	return native.closeErr
}

type fakeManagedService struct {
	applyErr    error
	verifyErr   error
	deleteErr   error
	closeErr    error
	applyCalls  int
	verifyCalls int
	deleteCalls int
	closeCalls  int
	onApply     func()
	onVerify    func()
}

func (service *fakeManagedService) Apply(Plan) error {
	service.applyCalls++
	if service.onApply != nil {
		service.onApply()
	}
	return service.applyErr
}

func (service *fakeManagedService) Verify(Plan) error {
	service.verifyCalls++
	if service.onVerify != nil {
		service.onVerify()
	}
	return service.verifyErr
}

func (service *fakeManagedService) Delete() error {
	service.deleteCalls++
	return service.deleteErr
}

func (service *fakeManagedService) Close() error {
	service.closeCalls++
	return service.closeErr
}

func TestProvisionOwnsCreateVerifyRollbackAndCommit(t *testing.T) {
	service := &fakeManagedService{}
	native := &fakeBackend{created: true, service: service}
	lease, err := provision(context.Background(), `C:\ProgramData\AgentWorkstationGateway`, native)
	if err != nil {
		t.Fatal(err)
	}
	if native.binaryPath != `C:\ProgramData\AgentWorkstationGateway\bin\awg-broker.exe` ||
		native.binaryMax != maxBrokerBytes || native.existsName != brokerservice.Name || native.createCalls != 1 ||
		service.applyCalls != 1 || service.verifyCalls != 1 {
		t.Fatal("provisioning did not execute the fixed verified sequence")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if service.deleteCalls != 1 || service.closeCalls != 1 {
		t.Fatal("uncommitted service was not deleted and closed")
	}

	service = &fakeManagedService{}
	native = &fakeBackend{created: true, service: service}
	lease, err = provision(context.Background(), `C:\ProgramData\AgentWorkstationGateway`, native)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if service.deleteCalls != 0 || service.closeCalls != 1 {
		t.Fatal("committed service was deleted or its handle was not released")
	}
}

func TestProvisionRejectsPreexistingServiceWithoutAdoption(t *testing.T) {
	native := &fakeBackend{exists: true, service: &fakeManagedService{}}
	lease, err := provision(context.Background(), `C:\ProgramData\AgentWorkstationGateway`, native)
	if lease != nil {
		t.Fatal("pre-existing service produced a lease")
	}
	assertInstallRule(t, err, "service-already-exists")
	if native.createCalls != 0 || native.service.deleteCalls != 0 {
		t.Fatal("pre-existing service was adopted or deleted")
	}
}

func TestProvisionStopsBeforeCreateOnPreflightFailures(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*fakeBackend, context.CancelFunc)
		rule  string
	}{
		{name: "binary", rule: "broker-binary-invalid", setup: func(native *fakeBackend, _ context.CancelFunc) {
			native.binaryErr = errors.New("synthetic binary failure")
		}},
		{name: "existence query", rule: "service-preflight-failed", setup: func(native *fakeBackend, _ context.CancelFunc) {
			native.existsErr = errors.New("synthetic existence failure")
		}},
		{name: "cancelled", rule: "context-cancelled", setup: func(_ *fakeBackend, cancel context.CancelFunc) {
			cancel()
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			native := &fakeBackend{created: true, service: &fakeManagedService{}}
			test.setup(native, cancel)
			lease, err := provision(ctx, `C:\ProgramData\AgentWorkstationGateway`, native)
			if lease != nil {
				t.Fatal("preflight failure produced a lease")
			}
			assertInstallRule(t, err, test.rule)
			if native.createCalls != 0 || native.service.deleteCalls != 0 {
				t.Fatal("preflight failure created or deleted a service")
			}
		})
	}
}

func TestProvisionRollsBackEveryPostCreateFailure(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*fakeManagedService, *fakeBackend, context.CancelFunc)
		rule  string
	}{
		{name: "create", rule: "service-create-failed", setup: func(service *fakeManagedService, native *fakeBackend, _ context.CancelFunc) {
			native.createErr = errors.New("synthetic create failure")
		}},
		{name: "apply", rule: "service-policy-apply-failed", setup: func(service *fakeManagedService, _ *fakeBackend, _ context.CancelFunc) {
			service.applyErr = errors.New("synthetic apply failure")
		}},
		{name: "cancel", rule: "context-cancelled", setup: func(service *fakeManagedService, _ *fakeBackend, cancel context.CancelFunc) {
			service.onApply = cancel
		}},
		{name: "verify", rule: "service-policy-verification-failed", setup: func(service *fakeManagedService, _ *fakeBackend, _ context.CancelFunc) {
			service.verifyErr = errors.New("synthetic verify failure")
		}},
		{name: "cancel after verify", rule: "context-cancelled", setup: func(service *fakeManagedService, _ *fakeBackend, cancel context.CancelFunc) {
			service.onVerify = cancel
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			service := &fakeManagedService{}
			native := &fakeBackend{created: true, service: service}
			test.setup(service, native, cancel)
			lease, err := provision(ctx, `C:\ProgramData\AgentWorkstationGateway`, native)
			if lease != nil {
				t.Fatal("failed provisioning produced a lease")
			}
			assertInstallRule(t, err, test.rule)
			if service.deleteCalls != 1 || service.closeCalls != 1 {
				t.Fatal("post-create failure did not roll back the owned service")
			}
		})
	}
}

func TestProvisionReportsRollbackFailure(t *testing.T) {
	service := &fakeManagedService{
		applyErr: errors.New("synthetic apply failure"), deleteErr: errors.New("synthetic delete failure"),
	}
	lease, err := provision(context.Background(), `C:\ProgramData\AgentWorkstationGateway`, &fakeBackend{
		created: true, service: service,
	})
	if lease != nil {
		t.Fatal("rollback failure produced a lease")
	}
	assertInstallRule(t, err, "service-rollback-failed")
}

func TestProvisionWithNativeClosesManagerAndRollsBackOnCloseFailure(t *testing.T) {
	failedService := &fakeManagedService{}
	failedNative := &fakeBackend{
		created: true, service: failedService, closeErr: errors.New("synthetic manager close failure"),
	}
	lease, err := provisionWithNative(
		context.Background(), `C:\ProgramData\AgentWorkstationGateway`, failedNative,
	)
	if lease != nil {
		t.Fatal("manager close failure produced a lease")
	}
	assertInstallRule(t, err, "scm-close-failed")
	if failedNative.closeCalls != 1 || failedService.deleteCalls != 1 || failedService.closeCalls != 1 {
		t.Fatal("manager close failure did not close the manager and roll back the service")
	}

	preflightNative := &fakeBackend{binaryErr: errors.New("synthetic binary failure")}
	lease, err = provisionWithNative(
		context.Background(), `C:\ProgramData\AgentWorkstationGateway`, preflightNative,
	)
	if lease != nil {
		t.Fatal("preflight failure produced a lease")
	}
	assertInstallRule(t, err, "broker-binary-invalid")
	if preflightNative.closeCalls != 1 {
		t.Fatal("preflight failure leaked the manager")
	}
}

func TestProvisionWithNativePrioritizesRollbackFailure(t *testing.T) {
	service := &fakeManagedService{deleteErr: errors.New("synthetic rollback failure")}
	native := &fakeBackend{
		created: true, service: service, closeErr: errors.New("synthetic manager close failure"),
	}
	lease, err := provisionWithNative(context.Background(), `C:\ProgramData\AgentWorkstationGateway`, native)
	if lease != nil {
		t.Fatal("rollback failure produced a lease")
	}
	assertInstallRule(t, err, "service-rollback-failed")
}

func TestFixedServiceProbeIsReadOnly(t *testing.T) {
	if _, err := ProbeFixedService(); err != nil {
		t.Fatal(err)
	}
}

func TestSCMInstallerAccessIsMinimal(t *testing.T) {
	expected := uint32(windows.SC_MANAGER_CONNECT | windows.SC_MANAGER_CREATE_SERVICE)
	if scmInstallerAccess != expected || scmInstallerAccess&windows.SC_MANAGER_ALL_ACCESS == windows.SC_MANAGER_ALL_ACCESS {
		t.Fatalf("unexpected SCM installer access mask: 0x%x", scmInstallerAccess)
	}
}
