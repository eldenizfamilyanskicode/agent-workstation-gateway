//go:build windows

package account

import (
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/accountprovision"
)

var advapi32 = windows.NewLazySystemDLL("advapi32.dll")
var lsaOpenPolicyProcedure = advapi32.NewProc("LsaOpenPolicy")
var lsaAddAccountRightsProcedure = advapi32.NewProc("LsaAddAccountRights")
var lsaEnumerateAccountRightsProcedure = advapi32.NewProc("LsaEnumerateAccountRights")
var lsaFreeMemoryProcedure = advapi32.NewProc("LsaFreeMemory")
var lsaCloseProcedure = advapi32.NewProc("LsaClose")

var controlRights = []string{
	"SeServiceLogonRight", "SeDenyInteractiveLogonRight", "SeDenyRemoteInteractiveLogonRight",
}
var executionRights = []string{
	"SeBatchLogonRight", "SeDenyInteractiveLogonRight", "SeDenyRemoteInteractiveLogonRight", "SeDenyServiceLogonRight",
}

type lsaObjectAttributes struct {
	length                   uint32
	rootDirectory            uintptr
	attributes               uint32
	securityDescriptor       uintptr
	securityQualityOfService uintptr
}

type lsaUnicodeString struct {
	length        uint16
	maximumLength uint16
	buffer        *uint16
}

func fixedRights(role accountprovision.Role) ([]string, bool) {
	switch role {
	case accountprovision.RoleControl:
		return append([]string(nil), controlRights...), true
	case accountprovision.RoleExecution:
		return append([]string(nil), executionRights...), true
	default:
		return nil, false
	}
}

func setAndVerifyRights(sid *windows.SID, rights []string) error {
	policy, err := openPolicy()
	if err != nil {
		return err
	}
	defer lsaCloseProcedure.Call(policy)
	nativeRights, keep, err := nativeRightStrings(rights)
	if err != nil {
		return err
	}
	status, _, _ := lsaAddAccountRightsProcedure.Call(
		policy, uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(&nativeRights[0])), uintptr(len(nativeRights)),
	)
	runtime.KeepAlive(keep)
	if status != 0 {
		return accountError("account-rights-add-failed")
	}
	actual, err := enumerateRights(policy, sid)
	if err != nil {
		return err
	}
	if !sameRights(actual, rights) {
		return accountError("account-rights-not-exact")
	}
	return nil
}

func openPolicy() (uintptr, error) {
	return openPolicyWithAccess(policyCreateAccount | policyLookupNames)
}

func openPolicyWithAccess(access uint32) (uintptr, error) {
	attributes := lsaObjectAttributes{length: uint32(unsafe.Sizeof(lsaObjectAttributes{}))}
	var policy uintptr
	status, _, _ := lsaOpenPolicyProcedure.Call(
		0, uintptr(unsafe.Pointer(&attributes)), uintptr(access), uintptr(unsafe.Pointer(&policy)),
	)
	if status != 0 || policy == 0 {
		return 0, accountError("lsa-policy-open-failed")
	}
	return policy, nil
}

func nativeRightStrings(rights []string) ([]lsaUnicodeString, [][]uint16, error) {
	native := make([]lsaUnicodeString, len(rights))
	keep := make([][]uint16, len(rights))
	for index, right := range rights {
		encoded, err := windows.UTF16FromString(right)
		if err != nil || len(encoded) < 2 || len(encoded) > 128 {
			return nil, nil, accountError("account-right-invalid")
		}
		keep[index] = encoded
		native[index] = lsaUnicodeString{
			length: uint16((len(encoded) - 1) * 2), maximumLength: uint16(len(encoded) * 2), buffer: &encoded[0],
		}
	}
	return native, keep, nil
}

func enumerateRights(policy uintptr, sid *windows.SID) ([]string, error) {
	var buffer *lsaUnicodeString
	var count uint32
	status, _, _ := lsaEnumerateAccountRightsProcedure.Call(
		policy, uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(&buffer)), uintptr(unsafe.Pointer(&count)),
	)
	if status != 0 || buffer == nil || count == 0 || count > 32 {
		return nil, accountError("account-rights-query-failed")
	}
	defer lsaFreeMemoryProcedure.Call(uintptr(unsafe.Pointer(buffer)))
	entries := unsafe.Slice(buffer, int(count))
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.buffer == nil || entry.length == 0 || entry.length%2 != 0 || entry.maximumLength < entry.length {
			return nil, accountError("account-rights-invalid")
		}
		result = append(result, windows.UTF16ToString(unsafe.Slice(entry.buffer, int(entry.length/2))))
	}
	return result, nil
}

func sameRights(actual []string, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	seen := make(map[string]struct{}, len(actual))
	for _, right := range actual {
		seen[strings.ToLower(right)] = struct{}{}
	}
	for _, right := range expected {
		if _, exists := seen[strings.ToLower(right)]; !exists {
			return false
		}
	}
	return true
}
