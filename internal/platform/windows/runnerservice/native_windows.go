//go:build windows

package runnerservice

import (
	"errors"
	"runtime"
	"syscall"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

var advapi32 = windows.NewLazySystemDLL("advapi32.dll")
var queryServiceObjectSecurityProcedure = advapi32.NewProc("QueryServiceObjectSecurity")
var setServiceObjectSecurityProcedure = advapi32.NewProc("SetServiceObjectSecurity")

const scmInstallerAccess = windows.SC_MANAGER_CONNECT | windows.SC_MANAGER_CREATE_SERVICE

type windowsBackend struct {
	manager *mgr.Mgr
}

type windowsService struct {
	service *mgr.Service
}

func ProbeFixedService() (exists bool, resultErr error) {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false, serviceError("scm-read-connect-failed")
	}
	defer func() {
		if windows.CloseServiceHandle(manager) != nil {
			exists = false
			resultErr = serviceError("scm-read-close-failed")
		}
	}()
	name, err := windows.UTF16PtrFromString(Name)
	if err != nil {
		return false, serviceError("service-name-invalid")
	}
	handle, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_STATUS)
	if err == nil {
		if windows.CloseServiceHandle(handle) != nil {
			return false, serviceError("service-read-close-failed")
		}
		return true, nil
	}
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return false, nil
	}
	return false, serviceError("service-read-query-failed")
}

func VerifyFixedService(installationRoot string, controlAccount string) error {
	plan, err := BuildPlan(installationRoot, controlAccount)
	if err != nil {
		return err
	}
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return serviceError("scm-read-connect-failed")
	}
	defer windows.CloseServiceHandle(manager)
	name, err := windows.UTF16PtrFromString(plan.Name)
	if err != nil {
		return serviceError("service-name-invalid")
	}
	handle, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_CONFIG|windows.READ_CONTROL)
	if err != nil {
		return serviceError("service-read-query-failed")
	}
	service := &windowsService{service: &mgr.Service{Name: plan.Name, Handle: handle}}
	verifyErr := service.Verify(plan)
	closeErr := service.Close()
	if verifyErr != nil || closeErr != nil {
		return serviceError("service-verification-failed")
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

func (native *windowsBackend) Create(plan Plan, password []byte) (managedService, bool, error) {
	configuration := stagedConfiguration(plan)
	name, err := windows.UTF16PtrFromString(plan.Name)
	if err != nil {
		return nil, false, err
	}
	display, err := windows.UTF16PtrFromString(configuration.DisplayName)
	if err != nil {
		return nil, false, err
	}
	command, err := windows.UTF16PtrFromString(configuration.BinaryPathName)
	if err != nil {
		return nil, false, err
	}
	account, err := windows.UTF16PtrFromString(configuration.ServiceStartName)
	if err != nil {
		return nil, false, err
	}
	dependencies, err := multiString(configuration.Dependencies)
	if err != nil {
		return nil, false, err
	}
	secret, err := mutableUTF16(password)
	if err != nil {
		return nil, false, err
	}
	defer zeroUTF16(secret)
	handle, err := windows.CreateService(
		native.manager.Handle, name, display, windows.SERVICE_ALL_ACCESS,
		configuration.ServiceType, configuration.StartType, configuration.ErrorControl,
		command, nil, nil, dependencies, account, &secret[0],
	)
	runtime.KeepAlive(password)
	if err != nil {
		return nil, false, err
	}
	return &windowsService{service: &mgr.Service{Name: plan.Name, Handle: handle}}, true, nil
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
		return serviceError("service-handle-invalid")
	}
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
	// Automatic start is enabled only after the exact DACL and bounded recovery
	// policy are present. Provision never calls Start.
	return service.service.UpdateConfig(plan.Configuration)
}

func (service *windowsService) Verify(plan Plan) error {
	if service == nil || service.service == nil {
		return serviceError("service-handle-invalid")
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
	if err := validateInstalledPolicy(plan, configuration, actions, resetPeriod, onNonCrash, command, rebootMessage); err != nil {
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
		return serviceError("service-security-policy-invalid")
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
		return serviceError("service-security-query-failed")
	}
	buffer := make([]byte, needed)
	result, _, _ = queryServiceObjectSecurityProcedure.Call(
		uintptr(handle), uintptr(information), uintptr(unsafe.Pointer(&buffer[0])), uintptr(needed), uintptr(unsafe.Pointer(&needed)),
	)
	if result == 0 {
		return serviceError("service-security-query-failed")
	}
	descriptor := (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(&buffer[0]))
	err := validateServiceDescriptor(descriptor)
	runtime.KeepAlive(buffer)
	return err
}

func multiString(values []string) (*uint16, error) {
	if len(values) == 0 {
		return nil, nil
	}
	encoded := make([]uint16, 0, 128)
	for _, value := range values {
		item, err := windows.UTF16FromString(value)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, item...)
	}
	encoded = append(encoded, 0)
	return &encoded[0], nil
}

func mutableUTF16(value []byte) ([]uint16, error) {
	if !validPassword(value) {
		return nil, serviceError("password-invalid")
	}
	result := make([]uint16, 0, len(value)+1)
	for len(value) > 0 {
		r, size := utf8.DecodeRune(value)
		if r == utf8.RuneError && size == 1 {
			zeroUTF16(result)
			return nil, serviceError("password-invalid")
		}
		if r <= 0xffff {
			result = append(result, uint16(r))
		} else {
			first, second := utf8RuneToSurrogate(r)
			result = append(result, first, second)
		}
		value = value[size:]
	}
	return append(result, 0), nil
}

func utf8RuneToSurrogate(r rune) (uint16, uint16) {
	value := uint32(r) - 0x10000
	return uint16(0xd800 + (value >> 10)), uint16(0xdc00 + (value & 0x3ff))
}

//go:noinline
func zeroUTF16(buffer []uint16) {
	for index := range buffer {
		buffer[index] = 0
	}
	runtime.KeepAlive(buffer)
}

var _ nativeBackend = (*windowsBackend)(nil)
var _ managedService = (*windowsService)(nil)
