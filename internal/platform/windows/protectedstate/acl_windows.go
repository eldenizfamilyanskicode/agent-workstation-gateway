//go:build windows

package protectedstate

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	FileSDDL      = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
	DirectorySDDL = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
)

type Error struct {
	Rule string
}

func (failure *Error) Error() string {
	return fmt.Sprintf("Windows protected-state ACL denied: %s", failure.Rule)
}

func ValidateFileDescriptor(descriptor *windows.SECURITY_DESCRIPTOR) error {
	return validateDescriptor(descriptor, false, false)
}

func ValidateExactFileDescriptor(descriptor *windows.SECURITY_DESCRIPTOR) error {
	return validateDescriptor(descriptor, false, true)
}

func ValidateExactDirectoryDescriptor(descriptor *windows.SECURITY_DESCRIPTOR) error {
	return validateDescriptor(descriptor, true, true)
}

func validateDescriptor(descriptor *windows.SECURITY_DESCRIPTOR, directory bool, exact bool) error {
	if descriptor == nil {
		return aclError("credential-acl-invalid")
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil ||
		(!owner.IsWellKnown(windows.WinLocalSystemSid) && !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)) {
		return aclError("credential-owner-denied")
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PRESENT == 0 || control&windows.SE_DACL_PROTECTED == 0 {
		return aclError("credential-acl-not-protected")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		return aclError("credential-acl-invalid")
	}
	if exact && dacl.AceCount != 2 {
		return aclError("credential-acl-not-exact")
	}

	systemAccess := false
	administratorsAccess := false
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil || ace == nil ||
			ace.Header.AceSize < uint16(unsafe.Offsetof(ace.SidStart)+8) || ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			return aclError("credential-ace-invalid")
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE && !exact {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return aclError("credential-ace-type-denied")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || int(ace.Header.AceSize) < int(unsafe.Offsetof(ace.SidStart))+sid.Len() {
			return aclError("credential-ace-invalid")
		}
		if exact && !exactAcePolicy(ace, directory) {
			return aclError("credential-ace-permissions-invalid")
		}
		canRead := ace.Mask&windows.FILE_READ_DATA != 0 && ace.Mask&windows.READ_CONTROL != 0
		switch {
		case sid.IsWellKnown(windows.WinLocalSystemSid):
			systemAccess = systemAccess || canRead
		case sid.IsWellKnown(windows.WinBuiltinAdministratorsSid):
			administratorsAccess = administratorsAccess || canRead
		default:
			return aclError("credential-ace-principal-denied")
		}
	}
	if !systemAccess || !administratorsAccess {
		return aclError("credential-acl-readers-incomplete")
	}
	return nil
}

func exactAcePolicy(ace *windows.ACCESS_ALLOWED_ACE, directory bool) bool {
	required := windows.ACCESS_MASK(
		windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER,
	)
	if ace.Mask&required != required {
		return false
	}
	flags := ace.Header.AceFlags
	if directory {
		return flags == windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE
	}
	return flags == 0
}

func aclError(rule string) error {
	return &Error{Rule: rule}
}
