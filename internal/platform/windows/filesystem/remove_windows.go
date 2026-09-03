//go:build windows

package filesystem

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
)

func RemoveInstalled(configuration installconfig.Config) error {
	if err := VerifyInstalled(configuration); err != nil {
		return filesystemError("installed-policy-conflict")
	}
	execution, err := executionSID(configuration.ExecutionIdentity.Identifier)
	if err != nil {
		return err
	}
	for _, path := range configuration.ApprovedRoots {
		if err := removeApprovedRootACE(path, execution); err != nil {
			return err
		}
	}
	for _, path := range []string{configuration.TempRoot, configuration.ProfileRoot} {
		if err := os.RemoveAll(path); err != nil {
			return filesystemError("isolated-root-remove-failed")
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return filesystemError("isolated-root-remove-incomplete")
		}
	}
	return nil
}

func removeApprovedRootACE(path string, execution *windows.SID) error {
	handle, err := openDirectory(path, windows.READ_CONTROL|windows.WRITE_DAC|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return filesystemError("approved-root-unavailable")
	}
	defer windows.CloseHandle(handle)
	descriptor, err := queryDescriptor(handle)
	if err != nil || !hasExactExecutionACE(descriptor, execution) {
		return filesystemError("approved-root-policy-mismatch")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return filesystemError("approved-root-dacl-invalid")
	}
	updated, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		accessEntry(execution, windows.REVOKE_ACCESS, 0, windows.TRUSTEE_IS_USER),
	}, dacl)
	if err != nil || setDACL(handle, updated, protectionUnchanged) != nil {
		return filesystemError("approved-root-ace-remove-failed")
	}
	after, err := queryDescriptor(handle)
	if err != nil || containsExecutionSID(after, execution) {
		return filesystemError("approved-root-ace-remove-verification-failed")
	}
	return nil
}

func containsExecutionSID(descriptor *windows.SECURITY_DESCRIPTOR, execution *windows.SID) bool {
	if descriptor == nil || execution == nil {
		return true
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return true
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, index, &ace) != nil || ace == nil ||
			ace.Header.AceSize < uint16(unsafe.Offsetof(ace.SidStart)+8) {
			return true
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.IsValid() && int(ace.Header.AceSize) >= int(unsafe.Offsetof(ace.SidStart))+sid.Len() && sid.Equals(execution) {
			return true
		}
	}
	return false
}
