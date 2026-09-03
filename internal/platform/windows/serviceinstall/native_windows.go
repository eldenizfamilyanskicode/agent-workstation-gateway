//go:build windows

package serviceinstall

import (
	"errors"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/brokerservice"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/protectedstate"
)

var advapi32 = windows.NewLazySystemDLL("advapi32.dll")
var queryServiceObjectSecurityProcedure = advapi32.NewProc("QueryServiceObjectSecurity")
var setServiceObjectSecurityProcedure = advapi32.NewProc("SetServiceObjectSecurity")

const maxBrokerBytes = protectedstate.MaxProtectedExecutableBytes

const scmInstallerAccess = windows.SC_MANAGER_CONNECT | windows.SC_MANAGER_CREATE_SERVICE

type windowsBackend struct {
	manager *mgr.Mgr
}

type windowsService struct {
	service *mgr.Service
}

// ProbeFixedService performs only a local, read-only existence query for the
// one fixed broker service. It does not open the mutating installer manager.
func ProbeFixedService() (exists bool, resultErr error) {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false, installError("scm-read-connect-failed")
	}
	defer func() {
		if windows.CloseServiceHandle(manager) != nil {
			exists = false
			resultErr = installError("scm-read-close-failed")
		}
	}()
	name, err := windows.UTF16PtrFromString(brokerservice.Name)
	if err != nil {
		return false, installError("service-name-invalid")
	}
	handle, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_STATUS)
	if err == nil {
		if windows.CloseServiceHandle(handle) != nil {
			return false, installError("service-read-close-failed")
		}
		return true, nil
	}
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return false, nil
	}
	return false, installError("service-read-query-failed")
}

func VerifyFixedService(installationRoot string) error {
	plan, err := BuildPlan(installationRoot)
	if err != nil {
		return err
	}
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return installError("scm-read-connect-failed")
	}
	defer windows.CloseServiceHandle(manager)
	name, err := windows.UTF16PtrFromString(plan.Name)
	if err != nil {
		return installError("service-name-invalid")
	}
	handle, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_CONFIG|windows.READ_CONTROL)
	if err != nil {
		return installError("service-read-query-failed")
	}
	service := &windowsService{service: &mgr.Service{Name: plan.Name, Handle: handle}}
	verifyErr := service.Verify(plan)
	closeErr := service.Close()
	if verifyErr != nil || closeErr != nil {
		return installError("service-verification-failed")
	}
	return nil
}

func newNativeBackend() (*windowsBackend, error) {
	handle, err := windows.OpenSCManager(nil, nil, scmInstallerAccess)
	if err != nil {
		return nil, err
	}
	return &windowsBackend{manager: &mgr.Mgr{Handle: handle}}, nil
}

func (native *windowsBackend) BinaryReady(path string, maximum int) error {
	return protectedstate.ValidateExactExecutable(path, maximum)
}

func (native *windowsBackend) ServiceExists(name string) (bool, error) {
	pointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false, err
	}
	handle, err := windows.OpenService(native.manager.Handle, pointer, windows.SERVICE_QUERY_STATUS)
	if err == nil {
		if err := windows.CloseServiceHandle(handle); err != nil {
			return false, err
		}
		return true, nil
	}
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return false, nil
	}
	return false, err
}

func (native *windowsBackend) Create(plan Plan) (managedService, bool, error) {
	configuration := createConfiguration(plan)
	service, err := native.manager.CreateService(
		plan.Name, plan.Executable, configuration, plan.Arguments...,
	)
	if err != nil {
		return nil, false, err
	}
	return &windowsService{service: service}, true, nil
}

func (native *windowsBackend) Close() error {
	if native == nil || native.manager == nil {
		return nil
	}
	err := native.manager.Disconnect()
	native.manager = nil
	return err
}

func (service *windowsService) Apply(plan Plan) error {
	if service == nil || service.service == nil {
		return installError("service-handle-invalid")
	}
	// Close the default service-object DACL before completing any optional
	// policy. The service was created disabled and cannot start in this state.
	if err := setServiceSecurity(service.service.Handle, plan.SecurityDescriptor); err != nil {
		return err
	}
	if err := service.service.SetRecoveryActions(plan.RecoveryActions, plan.RecoveryResetPeriodSeconds); err != nil {
		return err
	}
	if err := service.service.SetRecoveryCommand(""); err != nil {
		return err
	}
	if err := service.service.SetRebootMessage(""); err != nil {
		return err
	}
	if err := service.service.SetRecoveryActionsOnNonCrashFailures(plan.RecoveryOnNonCrash); err != nil {
		return err
	}
	// Enabling automatic start is the final mutation after every narrower
	// security and recovery setting has succeeded.
	return service.service.UpdateConfig(plan.Configuration)
}

func (service *windowsService) Verify(plan Plan) error {
	if service == nil || service.service == nil {
		return installError("service-handle-invalid")
	}
	configuration, err := service.service.Config()
	if err != nil {
		return err
	}
	actions, err := service.service.RecoveryActions()
	if err != nil {
		return err
	}
	resetPeriod, err := service.service.ResetPeriod()
	if err != nil {
		return err
	}
	onNonCrash, err := service.service.RecoveryActionsOnNonCrashFailures()
	if err != nil {
		return err
	}
	command, err := service.service.RecoveryCommand()
	if err != nil {
		return err
	}
	rebootMessage, err := service.service.RebootMessage()
	if err != nil {
		return err
	}
	if err := validateInstalledPolicy(
		plan, configuration, actions, resetPeriod, onNonCrash, command, rebootMessage,
	); err != nil {
		return err
	}
	return queryAndValidateServiceSecurity(service.service.Handle)
}

func (service *windowsService) Delete() error {
	if service == nil || service.service == nil {
		return nil
	}
	return service.service.Delete()
}

func (service *windowsService) Close() error {
	if service == nil || service.service == nil {
		return nil
	}
	err := service.service.Close()
	if err == nil {
		service.service = nil
	}
	return err
}

func setServiceSecurity(handle windows.Handle, sddl string) error {
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil || validateServiceDescriptor(descriptor) != nil {
		return installError("service-security-policy-invalid")
	}
	result, _, callErr := setServiceObjectSecurityProcedure.Call(
		uintptr(handle),
		uintptr(windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION),
		uintptr(unsafe.Pointer(descriptor)),
	)
	runtime.KeepAlive(descriptor)
	if result == 0 {
		return callErr
	}
	return nil
}

func queryAndValidateServiceSecurity(handle windows.Handle) error {
	information := windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION
	var needed uint32
	result, _, callErr := queryServiceObjectSecurityProcedure.Call(
		uintptr(handle), uintptr(information), 0, 0, uintptr(unsafe.Pointer(&needed)),
	)
	if result != 0 || !errors.Is(callErr, syscall.ERROR_INSUFFICIENT_BUFFER) || needed == 0 || needed > 64*1024 {
		return installError("service-security-query-failed")
	}
	buffer := make([]byte, needed)
	result, _, _ = queryServiceObjectSecurityProcedure.Call(
		uintptr(handle), uintptr(information), uintptr(unsafe.Pointer(&buffer[0])), uintptr(needed),
		uintptr(unsafe.Pointer(&needed)),
	)
	if result == 0 {
		return installError("service-security-query-failed")
	}
	descriptor := (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(&buffer[0]))
	err := validateServiceDescriptor(descriptor)
	runtime.KeepAlive(buffer)
	return err
}

var _ nativeBackend = (*windowsBackend)(nil)
var _ managedService = (*windowsService)(nil)
