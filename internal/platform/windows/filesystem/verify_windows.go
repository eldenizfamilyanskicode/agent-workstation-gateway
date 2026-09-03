//go:build windows

package filesystem

import (
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

func VerifyInstalled(configuration installconfig.Config) error {
	if configuration.Platform != platformpath.Windows || installconfig.Validate(configuration) != nil {
		return filesystemError("installed-configuration-invalid")
	}
	sid, err := executionSID(configuration.ExecutionIdentity.Identifier)
	if err != nil {
		return err
	}
	for _, path := range configuration.ApprovedRoots {
		handle, err := openDirectory(path, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
		if err != nil {
			return filesystemError("approved-root-unavailable")
		}
		descriptor, queryErr := queryDescriptor(handle)
		closeErr := windows.CloseHandle(handle)
		if queryErr != nil || closeErr != nil || !hasExactExecutionACE(descriptor, sid) {
			return filesystemError("approved-root-policy-mismatch")
		}
	}
	for _, path := range []string{configuration.ProfileRoot, configuration.TempRoot} {
		handle, err := openDirectory(path, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
		if err != nil {
			return filesystemError("isolated-root-unavailable")
		}
		descriptor, queryErr := queryDescriptor(handle)
		closeErr := windows.CloseHandle(handle)
		if queryErr != nil || closeErr != nil || validateIsolatedDescriptor(descriptor, sid) != nil {
			return filesystemError("isolated-root-policy-mismatch")
		}
	}
	return nil
}

func hasExactExecutionACE(descriptor *windows.SECURITY_DESCRIPTOR, execution *windows.SID) bool {
	if descriptor == nil || execution == nil {
		return false
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return false
	}
	count := 0
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var header *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, index, &header) != nil || header == nil ||
			header.Header.AceSize < uint16(unsafe.Offsetof(header.SidStart)+8) {
			return false
		}
		sid := (*windows.SID)(unsafe.Pointer(&header.SidStart))
		if !sid.IsValid() || int(header.Header.AceSize) < int(unsafe.Offsetof(header.SidStart))+sid.Len() || !sid.Equals(execution) {
			continue
		}
		if header.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || header.Header.AceFlags != directoryInheritance || header.Mask != executionModify {
			return false
		}
		count++
	}
	return count == 1
}
