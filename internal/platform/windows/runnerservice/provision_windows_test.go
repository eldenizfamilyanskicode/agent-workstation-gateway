//go:build windows

package runnerservice

import (
	"context"
	"errors"
	"testing"
)

var syntheticControlPassword = []byte("Synthetic-control-password-1!")

type fakeRunnerFiles struct {
	verifyCalls int
	verifyErr   error
}

func (files *fakeRunnerFiles) VerifyServiceExecutable(context.Context) error {
	files.verifyCalls++
	return files.verifyErr
}

type fakeBackend struct {
	exists      bool
	existsErr   error
	createErr   error
	created     bool
	service     *fakeManagedService
	existsCalls int
	createCalls int
	createPlan  Plan
	password    []byte
	closeCalls  int
	closeErr    error
}

func (native *fakeBackend) ServiceExists(string) (bool, error) {
	native.existsCalls++
	return native.exists, native.existsErr
}

func (native *fakeBackend) Create(plan Plan, password []byte) (managedService, bool, error) {
	native.createCalls++
	native.createPlan = plan
	native.password = password
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

func TestProvisionOwnsFixedServiceAndDoesNotRetainPassword(t *testing.T) {
	service := &fakeManagedService{}
	files := &fakeRunnerFiles{}
	native := &fakeBackend{created: true, service: service}
	lease, err := provision(context.Background(), `C:\ProgramData\AgentWorkstationGateway`, "awg-control", syntheticControlPassword, files, native)
	if err != nil {
		t.Fatal(err)
	}
	if files.verifyCalls != 1 || native.existsCalls != 1 || native.createCalls != 1 ||
		service.applyCalls != 1 || service.verifyCalls != 1 || native.createPlan.Name != Name ||
		len(native.password) == 0 {
		t.Fatal("runner service did not execute the fixed verify/create/apply/verify sequence")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if service.deleteCalls != 1 || service.closeCalls != 1 {
		t.Fatal("uncommitted runner service was not deleted and closed")
	}

	service = &fakeManagedService{}
	lease, err = provision(context.Background(), `C:\ProgramData\AgentWorkstationGateway`, "awg-control", syntheticControlPassword, &fakeRunnerFiles{}, &fakeBackend{created: true, service: service})
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
		t.Fatal("committed runner service was deleted or leaked")
	}
}

func TestProvisionRejectsPreexistingServiceWithoutAdoption(t *testing.T) {
	service := &fakeManagedService{}
	native := &fakeBackend{exists: true, created: true, service: service}
	lease, err := provision(context.Background(), `C:\ProgramData\AgentWorkstationGateway`, "awg-control", syntheticControlPassword, &fakeRunnerFiles{}, native)
	if lease != nil {
		t.Fatal("pre-existing runner service produced a lease")
	}
	assertServiceRule(t, err, "service-already-exists")
	if native.createCalls != 0 || service.deleteCalls != 0 {
		t.Fatal("pre-existing runner service was adopted or deleted")
	}
}

func TestPreflightFailuresStopBeforeServiceMutation(t *testing.T) {
	for _, test := range []struct {
		name   string
		files  *fakeRunnerFiles
		native *fakeBackend
		rule   string
	}{
		{name: "image", files: &fakeRunnerFiles{verifyErr: errors.New("synthetic")}, native: &fakeBackend{}, rule: "runner-service-image-invalid"},
		{name: "query", files: &fakeRunnerFiles{}, native: &fakeBackend{existsErr: errors.New("synthetic")}, rule: "service-preflight-failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			lease, err := provision(context.Background(), `C:\ProgramData\AgentWorkstationGateway`, "awg-control", syntheticControlPassword, test.files, test.native)
			if lease != nil {
				t.Fatal("preflight failure produced a lease")
			}
			assertServiceRule(t, err, test.rule)
			if test.native.createCalls != 0 {
				t.Fatal("preflight failure created a service")
			}
		})
	}
}

func TestEveryPostCreateFailureRollsBackOwnedService(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*fakeManagedService, *fakeBackend, context.CancelFunc)
		rule  string
	}{
		{name: "create", rule: "service-create-failed", setup: func(_ *fakeManagedService, native *fakeBackend, _ context.CancelFunc) {
			native.createErr = errors.New("synthetic")
		}},
		{name: "apply", rule: "service-policy-apply-failed", setup: func(service *fakeManagedService, _ *fakeBackend, _ context.CancelFunc) {
			service.applyErr = errors.New("synthetic")
		}},
		{name: "cancel", rule: "context-cancelled", setup: func(service *fakeManagedService, _ *fakeBackend, cancel context.CancelFunc) { service.onApply = cancel }},
		{name: "verify", rule: "service-policy-verification-failed", setup: func(service *fakeManagedService, _ *fakeBackend, _ context.CancelFunc) {
			service.verifyErr = errors.New("synthetic")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			service := &fakeManagedService{}
			native := &fakeBackend{created: true, service: service}
			test.setup(service, native, cancel)
			lease, err := provision(ctx, `C:\ProgramData\AgentWorkstationGateway`, "awg-control", syntheticControlPassword, &fakeRunnerFiles{}, native)
			if lease != nil {
				t.Fatal("failed runner service provisioning produced a lease")
			}
			assertServiceRule(t, err, test.rule)
			if service.deleteCalls != 1 || service.closeCalls != 1 {
				t.Fatal("created runner service was not rolled back")
			}
		})
	}
}

func TestMutablePasswordUTF16CanBeClearedWithoutEcho(t *testing.T) {
	secret, err := mutableUTF16([]byte("Synthetic-Contrøl-Password-1!"))
	if err != nil || len(secret) == 0 || secret[len(secret)-1] != 0 {
		t.Fatal("valid password could not be converted")
	}
	zeroUTF16(secret)
	for _, value := range secret {
		if value != 0 {
			t.Fatal("native service password buffer was not cleared")
		}
	}
	if _, err := mutableUTF16([]byte{'x', 0, 'y'}); err == nil {
		t.Fatal("NUL password was accepted")
	}
}
