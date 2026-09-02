//go:build windows

package filesystem

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/filesystemprovision"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

const (
	directoryFullAccess  windows.ACCESS_MASK = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff
	executionModify      windows.ACCESS_MASK = windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE | windows.FILE_GENERIC_EXECUTE | windows.DELETE
	directoryInheritance                     = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
)

type Native struct {
	executionIdentifier string
	approvedRoots       []string
	isolatedRoots       []string
}

type change struct {
	mu                sync.Mutex
	handle            windows.Handle
	path              string
	original          *windows.SECURITY_DESCRIPTOR
	originalProtected bool
	protectionChanged bool
	created           bool
	discarded         bool
}

type Error struct {
	Rule  string
	Cause error
}

func (failure *Error) Error() string {
	return fmt.Sprintf("Windows workload filesystem boundary failed: %s", failure.Rule)
}

func (failure *Error) Unwrap() error { return failure.Cause }

var _ filesystemprovision.Native = (*Native)(nil)
var _ filesystemprovision.Change = (*change)(nil)

func New(configuration installconfig.Config) (*Native, error) {
	if configuration.Platform != platformpath.Windows || installconfig.Validate(configuration) != nil {
		return nil, filesystemError("installed-configuration-invalid")
	}
	if _, err := executionSID(configuration.ExecutionIdentity.Identifier); err != nil {
		return nil, err
	}
	return &Native{
		executionIdentifier: configuration.ExecutionIdentity.Identifier,
		approvedRoots:       append([]string(nil), configuration.ApprovedRoots...),
		isolatedRoots:       []string{configuration.ProfileRoot, configuration.TempRoot},
	}, nil
}

func (native *Native) ConvergeApprovedRoot(path string, identifier string) (filesystemprovision.Change, error) {
	if native == nil || !strings.EqualFold(identifier, native.executionIdentifier) || !containsPath(native.approvedRoots, path) {
		return nil, filesystemError("approved-root-not-installed")
	}
	sid, err := executionSID(identifier)
	if err != nil {
		return nil, err
	}
	handle, err := openDirectory(path, windows.READ_CONTROL|windows.WRITE_DAC)
	if err != nil {
		return nil, err
	}
	return convergeApprovedHandle(handle, path, sid)
}

func (native *Native) ConvergeIsolatedRoot(path string, identifier string) (filesystemprovision.Change, error) {
	if native == nil || !strings.EqualFold(identifier, native.executionIdentifier) || !containsPath(native.isolatedRoots, path) {
		return nil, filesystemError("isolated-root-not-installed")
	}
	sid, err := executionSID(identifier)
	if err != nil {
		return nil, err
	}
	if err := validateDirectoryPath(path); err != nil {
		return nil, err
	}
	parent := filepath.Dir(path)
	if parent == path || !platformpath.Contains(platformpath.Windows, parent, path) {
		return nil, filesystemError("isolated-parent-invalid")
	}
	parentHandle, err := openDirectory(parent, windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return nil, filesystemError("isolated-parent-unavailable")
	}
	defer windows.CloseHandle(parentHandle)
	descriptor, err := creationDescriptor(sid)
	if err != nil {
		return nil, err
	}
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, filesystemError("directory-path-invalid")
	}
	attributes := windows.SecurityAttributes{
		Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor,
	}
	created := false
	if err := windows.CreateDirectory(pointer, &attributes); err != nil {
		if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return nil, filesystemCause("isolated-directory-create-failed", err)
		}
	} else {
		created = true
	}
	handle, err := openDirectory(path, windows.READ_CONTROL|windows.WRITE_DAC)
	if err != nil {
		if created {
			_ = windows.RemoveDirectory(pointer)
		}
		return nil, err
	}
	return convergeIsolatedHandle(handle, path, sid, created, descriptor)
}

func convergeApprovedHandle(handle windows.Handle, path string, sid *windows.SID) (result *change, resultErr error) {
	original, err := queryDescriptor(handle)
	if err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	protected, err := validateApprovedBaseline(original, sid)
	if err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	result = &change{handle: handle, path: path, original: original, originalProtected: protected}
	defer rollbackFailedChange(result, &result, &resultErr, "approved")
	dacl, _, _ := original.DACL()
	entries := []windows.EXPLICIT_ACCESS{
		accessEntry(sid, windows.REVOKE_ACCESS, 0, windows.TRUSTEE_IS_USER),
		accessEntry(sid, windows.GRANT_ACCESS, executionModify, windows.TRUSTEE_IS_USER),
	}
	updated, err := windows.ACLFromEntries(entries, dacl)
	if err != nil {
		return nil, filesystemError("approved-acl-build-failed")
	}
	if err := setDACL(handle, updated, protectionUnchanged); err != nil {
		return nil, err
	}
	actual, err := queryDescriptor(handle)
	if err == nil {
		err = validateApprovedApplied(actual, original, sid, protected)
	}
	if err != nil {
		return nil, filesystemCause("approved-acl-verification-failed", err)
	}
	return result, nil
}

func convergeIsolatedHandle(
	handle windows.Handle,
	path string,
	sid *windows.SID,
	created bool,
	creation *windows.SECURITY_DESCRIPTOR,
) (result *change, resultErr error) {
	var original *windows.SECURITY_DESCRIPTOR
	originalProtected := false
	if created {
		original = creation
		originalProtected = true
	} else {
		var err error
		original, err = queryDescriptor(handle)
		if err != nil {
			_ = windows.CloseHandle(handle)
			return nil, err
		}
		originalProtected, err = descriptorProtected(original)
		if err != nil {
			_ = windows.CloseHandle(handle)
			return nil, err
		}
		if dacl, _, daclErr := original.DACL(); daclErr != nil || dacl == nil {
			_ = windows.CloseHandle(handle)
			return nil, filesystemError("isolated-original-dacl-required")
		}
	}
	result = &change{
		handle: handle, path: path, original: original, originalProtected: originalProtected,
		protectionChanged: true, created: created,
	}
	defer rollbackFailedChange(result, &result, &resultErr, "isolated")
	descriptor, err := isolatedDescriptor(sid)
	if err != nil {
		return nil, err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return nil, filesystemError("isolated-descriptor-invalid")
	}
	if err := setDACL(handle, dacl, protectionEnabled); err != nil {
		return nil, err
	}
	actual, err := queryDescriptor(handle)
	if err == nil {
		err = validateIsolatedDescriptor(actual, sid)
	}
	if err != nil {
		return nil, filesystemCause("isolated-acl-verification-failed", err)
	}
	return result, nil
}

func rollbackFailedChange(owned *change, result **change, resultErr *error, kind string) func() {
	return func() {
		if *resultErr == nil || owned == nil {
			return
		}
		if err := owned.Rollback(); err != nil {
			*resultErr = filesystemError(kind + "-failure-rollback-failed")
		}
		owned.Discard()
		*result = nil
	}
}

func (item *change) Rollback() error {
	item.mu.Lock()
	defer item.mu.Unlock()
	return item.rollbackLocked()
}

func (item *change) rollbackLocked() error {
	if item.discarded {
		return nil
	}
	if !item.created {
		if item.handle == 0 || item.original == nil {
			return filesystemError("rollback-state-invalid")
		}
		dacl, _, err := item.original.DACL()
		if err != nil || dacl == nil {
			return filesystemError("rollback-descriptor-invalid")
		}
		protection := protectionUnchanged
		if item.protectionChanged {
			protection = protectionDisabled
			if item.originalProtected {
				protection = protectionEnabled
			}
		}
		if err := setDACL(item.handle, dacl, protection); err != nil {
			return filesystemError("rollback-acl-restore-failed")
		}
		actual, err := queryDescriptor(item.handle)
		if err != nil || !descriptorsEquivalent(actual, item.original) {
			return filesystemError("rollback-acl-verification-failed")
		}
		return nil
	}
	if item.handle == 0 || item.original == nil {
		return filesystemError("rollback-state-invalid")
	}
	dacl, _, err := item.original.DACL()
	if err != nil || dacl == nil {
		return filesystemError("rollback-descriptor-invalid")
	}
	if err := setDACL(item.handle, dacl, protectionEnabled); err != nil {
		return filesystemError("rollback-created-acl-restore-failed")
	}
	if item.handle != 0 {
		if err := windows.CloseHandle(item.handle); err != nil {
			return filesystemError("rollback-directory-close-failed")
		}
		item.handle = 0
	}
	pointer, err := windows.UTF16PtrFromString(item.path)
	if err != nil || windows.RemoveDirectory(pointer) != nil {
		return filesystemError("rollback-directory-remove-failed")
	}
	return nil
}

func (item *change) Discard() {
	item.mu.Lock()
	defer item.mu.Unlock()
	if item.discarded {
		return
	}
	if item.handle != 0 {
		_ = windows.CloseHandle(item.handle)
		item.handle = 0
	}
	item.original = nil
	item.path = ""
	item.discarded = true
}

type daclProtection uint8

const (
	protectionUnchanged daclProtection = iota
	protectionEnabled
	protectionDisabled
)

func setDACL(handle windows.Handle, dacl *windows.ACL, protection daclProtection) error {
	information := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	switch protection {
	case protectionEnabled:
		information |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	case protectionDisabled:
		information |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, information, nil, nil, dacl, nil); err != nil {
		return filesystemError("directory-acl-apply-failed")
	}
	return nil
}

func queryDescriptor(handle windows.Handle) (*windows.SECURITY_DESCRIPTOR, error) {
	descriptor, err := windows.GetSecurityInfo(
		handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil {
		return nil, filesystemError("directory-acl-query-failed")
	}
	return descriptor, nil
}

func isolatedDescriptor(execution *windows.SID) (*windows.SECURITY_DESCRIPTOR, error) {
	sddl := fmt.Sprintf(
		"D:P(A;OICI;0x%x;;;SY)(A;OICI;0x%x;;;BA)(A;OICI;0x%x;;;%s)",
		directoryFullAccess, directoryFullAccess, executionModify, execution.String(),
	)
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, filesystemError("isolated-descriptor-build-failed")
	}
	return descriptor, nil
}

func creationDescriptor(execution *windows.SID) (*windows.SECURITY_DESCRIPTOR, error) {
	creator, err := currentUserSID()
	if err != nil {
		return nil, err
	}
	sddl := fmt.Sprintf(
		"D:P(A;OICI;0x%x;;;SY)(A;OICI;0x%x;;;BA)(A;OICI;0x%x;;;%s)(A;OICI;0x%x;;;%s)",
		directoryFullAccess, directoryFullAccess, executionModify, execution.String(), directoryFullAccess, creator.String(),
	)
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, filesystemError("creation-descriptor-build-failed")
	}
	return descriptor, nil
}

func currentUserSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return nil, filesystemError("installer-sid-unavailable")
	}
	copy, err := user.User.Sid.Copy()
	if err != nil {
		return nil, filesystemError("installer-sid-copy-failed")
	}
	return copy, nil
}

func accessEntry(sid *windows.SID, mode windows.ACCESS_MODE, mask windows.ACCESS_MASK, trusteeType windows.TRUSTEE_TYPE) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: mask,
		AccessMode:        mode,
		Inheritance:       directoryInheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: trusteeType,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func validateApprovedBaseline(descriptor *windows.SECURITY_DESCRIPTOR, execution *windows.SID) (bool, error) {
	protected, err := descriptorProtected(descriptor)
	if err != nil {
		return false, err
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || owner.Equals(execution) {
		return false, filesystemError("approved-owner-invalid")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return false, filesystemError("approved-dacl-required")
	}
	if err := validateSupportedACL(dacl); err != nil {
		return false, err
	}
	if err := validateBroadPrincipalRights(dacl); err != nil {
		return false, err
	}
	return protected, nil
}

func validateApprovedApplied(actual *windows.SECURITY_DESCRIPTOR, original *windows.SECURITY_DESCRIPTOR, execution *windows.SID, protected bool) error {
	actualProtected, err := validateApprovedBaseline(actual, execution)
	if err != nil {
		return err
	}
	if actualProtected != protected {
		return filesystemError("approved-protection-changed")
	}
	actualOwner, _, _ := actual.Owner()
	originalOwner, _, _ := original.Owner()
	if actualOwner == nil || originalOwner == nil || !actualOwner.Equals(originalOwner) {
		return filesystemError("approved-owner-changed")
	}
	dacl, _, _ := actual.DACL()
	directFound := false
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		ace, sid, err := aclEntry(dacl, index)
		if err != nil {
			return err
		}
		if !sid.Equals(execution) {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			return filesystemError("approved-execution-ace-conflict")
		}
		if directFound || ace.Mask != executionModify || ace.Header.AceFlags != directoryInheritance {
			return filesystemError("approved-execution-ace-not-exact")
		}
		directFound = true
	}
	if !directFound {
		return filesystemError("approved-execution-ace-missing")
	}
	return nil
}

func validateIsolatedDescriptor(descriptor *windows.SECURITY_DESCRIPTOR, execution *windows.SID) error {
	protected, err := descriptorProtected(descriptor)
	if err != nil || !protected {
		return filesystemError("isolated-dacl-not-protected")
	}
	owner, _, err := descriptor.Owner()
	if err != nil || (owner != nil && owner.Equals(execution)) {
		return filesystemError("isolated-owner-invalid")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return filesystemError("isolated-dacl-required")
	}
	if dacl.AceCount != 3 {
		return filesystemError("isolated-ace-count-invalid")
	}
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	administrators, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	expected := map[string]windows.ACCESS_MASK{
		system.String(): directoryFullAccess, administrators.String(): directoryFullAccess, execution.String(): executionModify,
	}
	seen := make(map[string]bool, len(expected))
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		ace, sid, err := aclEntry(dacl, index)
		if err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != directoryInheritance {
			return filesystemError("isolated-ace-shape-invalid")
		}
		mask, ok := expected[sid.String()]
		if !ok || seen[sid.String()] {
			return filesystemError("isolated-ace-principal-invalid")
		}
		if ace.Mask != mask {
			return filesystemError("isolated-ace-mask-invalid")
		}
		seen[sid.String()] = true
	}
	if len(seen) != len(expected) || executionModify&(windows.WRITE_DAC|windows.WRITE_OWNER) != 0 {
		return filesystemError("isolated-principal-set-invalid")
	}
	return nil
}

func validateSupportedACL(dacl *windows.ACL) error {
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		ace, _, err := aclEntry(dacl, index)
		if err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE {
			return filesystemError("unsupported-approved-ace")
		}
	}
	return nil
}

func validateBroadPrincipalRights(dacl *windows.ACL) error {
	broad := make([]*windows.SID, 0, 3)
	for _, sidType := range []windows.WELL_KNOWN_SID_TYPE{
		windows.WinWorldSid,
		windows.WinAuthenticatedUserSid,
		windows.WinBuiltinUsersSid,
		windows.WinLocalAccountSid,
		windows.WinBatchSid,
	} {
		sid, err := windows.CreateWellKnownSid(sidType)
		if err != nil {
			return filesystemError("well-known-sid-unavailable")
		}
		broad = append(broad, sid)
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		ace, sid, err := aclEntry(dacl, index)
		if err != nil {
			return err
		}
		if !sidIn(broad, sid) {
			continue
		}
		generic := windows.ACCESS_MASK(windows.GENERIC_READ | windows.GENERIC_WRITE | windows.GENERIC_EXECUTE | windows.GENERIC_ALL)
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE && ace.Mask&(executionModify|generic) != 0 {
			return filesystemError("broad-deny-conflicts-with-execution")
		}
		if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE && ace.Mask&(windows.WRITE_DAC|windows.WRITE_OWNER|windows.GENERIC_ALL) != 0 {
			return filesystemError("broad-principal-can-manage-acl")
		}
	}
	return nil
}

func aclEntry(dacl *windows.ACL, index uint32) (*windows.ACCESS_ALLOWED_ACE, *windows.SID, error) {
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil {
		return nil, nil, filesystemError("ace-query-failed")
	}
	minimum := uintptr(unsafe.Offsetof(ace.SidStart)) + 8
	if uintptr(ace.Header.AceSize) < minimum {
		return nil, nil, filesystemError("ace-size-invalid")
	}
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !sid.IsValid() || uintptr(ace.Header.AceSize) < uintptr(unsafe.Offsetof(ace.SidStart))+uintptr(sid.Len()) {
		return nil, nil, filesystemError("ace-sid-invalid")
	}
	return ace, sid, nil
}

func descriptorProtected(descriptor *windows.SECURITY_DESCRIPTOR) (bool, error) {
	if descriptor == nil || !descriptor.IsValid() {
		return false, filesystemError("descriptor-invalid")
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PRESENT == 0 {
		return false, filesystemError("descriptor-control-invalid")
	}
	return control&windows.SE_DACL_PROTECTED != 0, nil
}

func descriptorsEquivalent(left *windows.SECURITY_DESCRIPTOR, right *windows.SECURITY_DESCRIPTOR) bool {
	leftProtected, leftErr := descriptorProtected(left)
	rightProtected, rightErr := descriptorProtected(right)
	if leftErr != nil || rightErr != nil || leftProtected != rightProtected {
		return false
	}
	leftOwner, _, leftErr := left.Owner()
	rightOwner, _, rightErr := right.Owner()
	if leftErr != nil || rightErr != nil || leftOwner == nil || rightOwner == nil || !leftOwner.Equals(rightOwner) {
		return false
	}
	leftDACL, _, leftErr := left.DACL()
	rightDACL, _, rightErr := right.DACL()
	if leftErr != nil || rightErr != nil || leftDACL == nil || rightDACL == nil || leftDACL.AceCount != rightDACL.AceCount {
		return false
	}
	for index := uint32(0); index < uint32(leftDACL.AceCount); index++ {
		leftACE, leftErr := rawACE(leftDACL, index)
		rightACE, rightErr := rawACE(rightDACL, index)
		if leftErr != nil || rightErr != nil || !bytes.Equal(leftACE, rightACE) {
			return false
		}
	}
	return true
}

func rawACE(dacl *windows.ACL, index uint32) ([]byte, error) {
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil || ace.Header.AceSize < uint16(unsafe.Sizeof(windows.ACE_HEADER{})) {
		return nil, filesystemError("ace-query-failed")
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(ace)), int(ace.Header.AceSize)), nil
}

func executionSID(identifier string) (*windows.SID, error) {
	sid, err := windows.StringToSid(identifier)
	if err != nil || sid == nil || !sid.IsValid() || sid.SubAuthorityCount() < 4 || !strings.HasPrefix(strings.ToUpper(sid.String()), "S-1-5-21-") {
		return nil, filesystemError("execution-sid-invalid")
	}
	return sid, nil
}

func openDirectory(path string, access uint32) (windows.Handle, error) {
	if err := validateDirectoryPath(path); err != nil {
		return 0, err
	}
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, filesystemError("directory-path-invalid")
	}
	handle, err := windows.CreateFile(
		pointer, access, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0,
	)
	if err != nil {
		return 0, filesystemCause("directory-open-failed", err)
	}
	if err := validateDirectoryHandle(handle, path); err != nil {
		_ = windows.CloseHandle(handle)
		return 0, err
	}
	return handle, nil
}

func validateDirectoryHandle(handle windows.Handle, expected string) error {
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return filesystemError("directory-query-failed")
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return filesystemError("directory-type-denied")
	}
	final, err := finalPath(handle)
	if err != nil || !platformpath.Equal(platformpath.Windows, final, expected) {
		return filesystemError("directory-alias-rejected")
	}
	return nil
}

func finalPath(handle windows.Handle) (string, error) {
	buffer := make([]uint16, 512)
	for {
		length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
		if err != nil {
			return "", filesystemError("final-path-query-failed")
		}
		if length < uint32(len(buffer)) {
			path := string(utf16.Decode(buffer[:length]))
			if strings.HasPrefix(path, `\\?\UNC\`) {
				return "", filesystemError("unc-path-denied")
			}
			path = strings.TrimPrefix(path, `\\?\`)
			if len(path) >= 2 && path[1] == ':' && path[0] >= 'a' && path[0] <= 'z' {
				path = strings.ToUpper(path[:1]) + path[1:]
			}
			if err := validateDirectoryPath(path); err != nil {
				return "", err
			}
			return path, nil
		}
		if length > platformpath.MaxPathBytes {
			return "", filesystemError("final-path-invalid")
		}
		buffer = make([]uint16, int(length)+1)
	}
}

func validateDirectoryPath(path string) error {
	if err := platformpath.ValidateAbsolute(platformpath.Windows, path); err != nil || platformpath.IsFilesystemRoot(platformpath.Windows, path) {
		return filesystemError("directory-path-invalid")
	}
	return nil
}

func containsPath(allowed []string, candidate string) bool {
	for _, path := range allowed {
		if platformpath.Equal(platformpath.Windows, path, candidate) {
			return true
		}
	}
	return false
}

func sidIn(allowed []*windows.SID, candidate *windows.SID) bool {
	for _, sid := range allowed {
		if sid.Equals(candidate) {
			return true
		}
	}
	return false
}

func filesystemError(rule string) error {
	return &Error{Rule: rule}
}

func filesystemCause(rule string, cause error) error {
	return &Error{Rule: rule, Cause: cause}
}
