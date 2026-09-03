//go:build windows

package account

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/accountprovision"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

const (
	userPrivUser             = 1
	userScript               = 0x0001
	userNormalAccount        = 0x0200
	userPasswordNeverExpires = 0x10000
	netUserNotFound          = syscall.Errno(2221)
	maxPreferredLength       = 0xffffffff
	localGroupsIndirect      = 1
	policyCreateAccount      = 0x00000010
	policyLookupNames        = 0x00000800
)

var netapi32 = windows.NewLazySystemDLL("netapi32.dll")
var netUserAddProcedure = netapi32.NewProc("NetUserAdd")
var netUserDelProcedure = netapi32.NewProc("NetUserDel")
var netLocalGroupAddMembersProcedure = netapi32.NewProc("NetLocalGroupAddMembers")
var netUserGetLocalGroupsProcedure = netapi32.NewProc("NetUserGetLocalGroups")

type Native struct {
	controlAccount   string
	executionAccount string
	mu               sync.Mutex
	created          map[string]struct{}
}

type Error struct {
	Rule string
}

func (failure *Error) Error() string {
	return fmt.Sprintf("Windows account boundary failed: %s", failure.Rule)
}

var _ accountprovision.Native = (*Native)(nil)

func VerifyInstalled(configuration installconfig.Config) error {
	if configuration.Platform != platformpath.Windows || installconfig.Validate(configuration) != nil {
		return accountError("installed-configuration-invalid")
	}
	principals := []struct {
		role      accountprovision.Role
		principal installconfig.Principal
	}{
		{accountprovision.RoleControl, configuration.ControlIdentity},
		{accountprovision.RoleExecution, configuration.ExecutionIdentity},
	}
	for _, installed := range principals {
		role, principal := installed.role, installed.principal
		sid, _, accountType, err := windows.LookupSID("", principal.Name)
		if err != nil || sid == nil || !sid.IsValid() || accountType != windows.SidTypeUser || sid.String() != principal.Identifier {
			return accountError("installed-account-identity-mismatch")
		}
		if err := verifyUsersOnly(principal.Name); err != nil {
			return err
		}
		rights, _ := fixedRights(role)
		policy, err := openPolicyWithAccess(policyLookupNames)
		if err != nil {
			return err
		}
		actual, rightsErr := enumerateRights(policy, sid)
		lsaCloseProcedure.Call(policy)
		if rightsErr != nil || !sameRights(actual, rights) {
			return accountError("installed-account-rights-mismatch")
		}
	}
	return nil
}

func DeleteInstalled(configuration installconfig.Config) error {
	if err := VerifyInstalled(configuration); err != nil {
		return accountError("installed-account-policy-conflict")
	}
	for _, name := range []string{configuration.ExecutionIdentity.Name, configuration.ControlIdentity.Name} {
		if err := deleteAccount(name); err != nil {
			return accountError("installed-account-delete-failed")
		}
	}
	return nil
}

func NewNative(specification installplan.Spec) (*Native, error) {
	if _, err := installplan.Build(specification); err != nil {
		return nil, accountError("install-plan-invalid")
	}
	return &Native{
		controlAccount: specification.ControlAccount, executionAccount: specification.ExecutionAccount,
		created: make(map[string]struct{}),
	}, nil
}

func (native *Native) AccountExists(name string) (bool, error) {
	if !native.allowed(name) {
		return false, accountError("account-name-denied")
	}
	namePointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false, accountError("account-name-invalid")
	}
	var buffer *byte
	err = windows.NetUserGetInfo(nil, namePointer, 10, &buffer)
	if err == nil {
		if buffer != nil {
			_ = windows.NetApiBufferFree(buffer)
		}
		return true, nil
	}
	if errors.Is(err, netUserNotFound) {
		return false, nil
	}
	return false, accountError("account-query-failed")
}

func (native *Native) CreateAccount(name string, password []byte) (accountprovision.Account, bool, error) {
	if !native.allowed(name) {
		return accountprovision.Account{}, false, accountError("account-name-denied")
	}
	nameUTF16, err := windows.UTF16FromString(name)
	if err != nil {
		return accountprovision.Account{}, false, accountError("account-name-invalid")
	}
	passwordUTF16, err := mutableUTF16(password)
	if err != nil {
		return accountprovision.Account{}, false, err
	}
	defer zeroUTF16(passwordUTF16)
	comment, err := windows.UTF16FromString("Agent Workstation Gateway managed account")
	if err != nil {
		return accountprovision.Account{}, false, accountError("account-comment-invalid")
	}
	information := userInfo1{
		name: &nameUTF16[0], password: &passwordUTF16[0], privilege: userPrivUser,
		comment: &comment[0], flags: userScript | userNormalAccount | userPasswordNeverExpires,
	}
	var parameterError uint32
	status, _, _ := netUserAddProcedure.Call(
		0, 1, uintptr(unsafe.Pointer(&information)), uintptr(unsafe.Pointer(&parameterError)),
	)
	if status != 0 {
		return accountprovision.Account{}, false, accountError("account-create-failed")
	}
	native.mu.Lock()
	native.created[strings.ToLower(name)] = struct{}{}
	native.mu.Unlock()
	sid, _, accountType, err := windows.LookupSID("", name)
	if err != nil || sid == nil || !sid.IsValid() || accountType != windows.SidTypeUser {
		return accountprovision.Account{Name: name}, true, accountError("account-sid-lookup-failed")
	}
	usersSID, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		return accountprovision.Account{Name: name}, true, accountError("primary-group-sid-failed")
	}
	return accountprovision.Account{
		Name: name, Identifier: sid.String(), PrimaryGroupIdentifier: usersSID.String(),
	}, true, nil
}

func (native *Native) ApplyPolicy(role accountprovision.Role, account accountprovision.Account) error {
	if !native.owns(account.Name) {
		return accountError("account-not-transaction-owned")
	}
	rights, ok := fixedRights(role)
	if !ok {
		return accountError("account-role-invalid")
	}
	if role == accountprovision.RoleControl && !strings.EqualFold(account.Name, native.controlAccount) ||
		role == accountprovision.RoleExecution && !strings.EqualFold(account.Name, native.executionAccount) {
		return accountError("account-role-mismatch")
	}
	sid, err := windows.StringToSid(account.Identifier)
	if err != nil || sid == nil || !sid.IsValid() {
		return accountError("account-sid-invalid")
	}
	if err := ensureUsersOnly(account.Name, sid); err != nil {
		return err
	}
	if err := setAndVerifyRights(sid, rights); err != nil {
		return err
	}
	return nil
}

func (native *Native) DeleteAccount(name string) error {
	if !native.owns(name) {
		return accountError("account-not-transaction-owned")
	}
	if err := deleteAccount(name); err != nil {
		return accountError("account-delete-failed")
	}
	native.mu.Lock()
	delete(native.created, strings.ToLower(name))
	native.mu.Unlock()
	return nil
}

func (native *Native) owns(name string) bool {
	if native == nil {
		return false
	}
	native.mu.Lock()
	defer native.mu.Unlock()
	_, exists := native.created[strings.ToLower(name)]
	return exists
}

func (native *Native) allowed(name string) bool {
	return native != nil && (strings.EqualFold(name, native.controlAccount) || strings.EqualFold(name, native.executionAccount))
}

type userInfo1 struct {
	name        *uint16
	password    *uint16
	passwordAge uint32
	privilege   uint32
	homeDir     *uint16
	comment     *uint16
	flags       uint32
	scriptPath  *uint16
}

type localGroupMembersInfo0 struct {
	sid *windows.SID
}

type localGroupUsersInfo0 struct {
	name *uint16
}

func ensureUsersOnly(name string, sid *windows.SID) error {
	usersSID, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		return accountError("users-group-sid-failed")
	}
	usersName, _, _, err := usersSID.LookupAccount("")
	if err != nil {
		return accountError("users-group-name-failed")
	}
	groupPointer, err := windows.UTF16PtrFromString(usersName)
	if err != nil {
		return accountError("users-group-name-invalid")
	}
	member := localGroupMembersInfo0{sid: sid}
	status, _, _ := netLocalGroupAddMembersProcedure.Call(
		0, uintptr(unsafe.Pointer(groupPointer)), 0, uintptr(unsafe.Pointer(&member)), 1,
	)
	if status != 0 && status != uintptr(windows.ERROR_MEMBER_IN_ALIAS) {
		return accountError("users-group-add-failed")
	}
	return verifyUsersOnly(name)
}

func verifyUsersOnly(name string) error {
	usersSID, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		return accountError("users-group-sid-failed")
	}
	usersName, _, _, err := usersSID.LookupAccount("")
	if err != nil {
		return accountError("users-group-name-failed")
	}
	groups, err := localGroups(name)
	if err != nil {
		return err
	}
	if len(groups) != 1 || !strings.EqualFold(groups[0], usersName) {
		return accountError("unexpected-group-membership")
	}
	return nil
}

func localGroups(name string) ([]string, error) {
	namePointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, accountError("account-name-invalid")
	}
	var buffer *byte
	var entriesRead uint32
	var totalEntries uint32
	status, _, _ := netUserGetLocalGroupsProcedure.Call(
		0, uintptr(unsafe.Pointer(namePointer)), 0, localGroupsIndirect,
		uintptr(unsafe.Pointer(&buffer)), maxPreferredLength,
		uintptr(unsafe.Pointer(&entriesRead)), uintptr(unsafe.Pointer(&totalEntries)),
	)
	if status != 0 || entriesRead != totalEntries || entriesRead > 64 {
		if buffer != nil {
			_ = windows.NetApiBufferFree(buffer)
		}
		return nil, accountError("group-membership-query-failed")
	}
	if buffer == nil && entriesRead != 0 {
		return nil, accountError("group-membership-query-failed")
	}
	defer func() {
		if buffer != nil {
			_ = windows.NetApiBufferFree(buffer)
		}
	}()
	entries := unsafe.Slice((*localGroupUsersInfo0)(unsafe.Pointer(buffer)), int(entriesRead))
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.name == nil {
			return nil, accountError("group-membership-invalid")
		}
		result = append(result, windows.UTF16PtrToString(entry.name))
	}
	return result, nil
}

func deleteAccount(name string) error {
	namePointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	status, _, _ := netUserDelProcedure.Call(0, uintptr(unsafe.Pointer(namePointer)))
	if status != 0 && status != uintptr(netUserNotFound) {
		return syscall.Errno(status)
	}
	return nil
}

func mutableUTF16(value []byte) ([]uint16, error) {
	if len(value) == 0 || len(value) > 256 || !utf8.Valid(value) {
		return nil, accountError("password-invalid")
	}
	result := make([]uint16, 0, len(value)+1)
	for len(value) > 0 {
		runeValue, size := utf8.DecodeRune(value)
		if runeValue == utf8.RuneError && size == 1 || runeValue == 0 {
			zeroUTF16(result)
			return nil, accountError("password-invalid")
		}
		if runeValue <= 0xffff {
			result = append(result, uint16(runeValue))
		} else {
			high, low := utf16.EncodeRune(runeValue)
			result = append(result, uint16(high), uint16(low))
		}
		value = value[size:]
	}
	return append(result, 0), nil
}

func zeroUTF16(buffer []uint16) {
	for index := range buffer {
		buffer[index] = 0
	}
	runtime.KeepAlive(buffer)
}

func accountError(rule string) error {
	return &Error{Rule: rule}
}
