//go:build windows

package process

import (
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

type credentialBlobReader interface {
	Read() ([]byte, error)
}

type protectedCredentialFile struct {
	path string
}

func (file protectedCredentialFile) Read() ([]byte, error) {
	pathPointer, err := windows.UTF16PtrFromString(file.path)
	if err != nil {
		return nil, boundaryError("credential-path-invalid")
	}
	handle, err := windows.CreateFile(
		pathPointer,
		windows.GENERIC_READ|windows.READ_CONTROL,
		0,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_SEQUENTIAL_SCAN,
		0,
	)
	if err != nil {
		return nil, boundaryError("credential-file-open-failed")
	}
	defer windows.CloseHandle(handle)

	information, err := credentialFileInformation(handle)
	if err != nil {
		return nil, err
	}
	canonical, err := credentialFinalPath(handle)
	if err != nil || !platformpath.Equal(platformpath.Windows, canonical, file.path) {
		return nil, boundaryError("credential-file-alias-rejected")
	}
	securityDescriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || securityDescriptor == nil {
		return nil, boundaryError("credential-acl-query-failed")
	}
	if err := validateCredentialSecurityDescriptor(securityDescriptor); err != nil {
		return nil, err
	}

	protected := make([]byte, int(information.FileSizeLow))
	read := 0
	for read < len(protected) {
		var count uint32
		if err := windows.ReadFile(handle, protected[read:], &count, nil); err != nil || count == 0 {
			zeroBytes(protected)
			return nil, boundaryError("credential-file-read-failed")
		}
		read += int(count)
	}
	after, err := credentialFileInformation(handle)
	if err != nil || after.FileSizeHigh != information.FileSizeHigh || after.FileSizeLow != information.FileSizeLow ||
		after.FileIndexHigh != information.FileIndexHigh || after.FileIndexLow != information.FileIndexLow {
		zeroBytes(protected)
		return nil, boundaryError("credential-file-changed")
	}
	return protected, nil
}

func credentialFileInformation(handle windows.Handle) (windows.ByHandleFileInformation, error) {
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return information, boundaryError("credential-file-query-failed")
	}
	if information.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
		information.FileSizeHigh != 0 || information.FileSizeLow == 0 || information.FileSizeLow > maxProtectedBlobBytes {
		return information, boundaryError("credential-file-invalid")
	}
	return information, nil
}

func credentialFinalPath(handle windows.Handle) (string, error) {
	buffer := make([]uint16, 512)
	for {
		length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
		if err != nil {
			return "", boundaryError("credential-final-path-query-failed")
		}
		if length < uint32(len(buffer)) {
			path := string(utf16.Decode(buffer[:length]))
			if strings.HasPrefix(path, `\\?\UNC\`) {
				return "", boundaryError("credential-unc-path-rejected")
			}
			path = strings.TrimPrefix(path, `\\?\`)
			if len(path) >= 2 && path[1] == ':' && path[0] >= 'a' && path[0] <= 'z' {
				path = strings.ToUpper(path[:1]) + path[1:]
			}
			if err := platformpath.ValidateAbsolute(platformpath.Windows, path); err != nil {
				return "", boundaryError("credential-final-path-invalid")
			}
			return path, nil
		}
		if length > platformpath.MaxPathBytes {
			return "", boundaryError("credential-final-path-invalid")
		}
		buffer = make([]uint16, int(length)+1)
	}
}

func validateCredentialSecurityDescriptor(descriptor *windows.SECURITY_DESCRIPTOR) error {
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil ||
		(!owner.IsWellKnown(windows.WinLocalSystemSid) && !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)) {
		return boundaryError("credential-owner-denied")
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PRESENT == 0 || control&windows.SE_DACL_PROTECTED == 0 {
		return boundaryError("credential-acl-not-protected")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		return boundaryError("credential-acl-invalid")
	}

	systemRead := false
	administratorsRead := false
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil || ace == nil ||
			ace.Header.AceSize < uint16(unsafe.Offsetof(ace.SidStart)+8) || ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			return boundaryError("credential-ace-invalid")
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return boundaryError("credential-ace-type-denied")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || int(ace.Header.AceSize) < int(unsafe.Offsetof(ace.SidStart))+sid.Len() {
			return boundaryError("credential-ace-invalid")
		}
		canRead := ace.Mask&windows.FILE_READ_DATA != 0 && ace.Mask&windows.READ_CONTROL != 0
		switch {
		case sid.IsWellKnown(windows.WinLocalSystemSid):
			systemRead = systemRead || canRead
		case sid.IsWellKnown(windows.WinBuiltinAdministratorsSid):
			administratorsRead = administratorsRead || canRead
		default:
			return boundaryError("credential-ace-principal-denied")
		}
	}
	if !systemRead || !administratorsRead {
		return boundaryError("credential-acl-readers-incomplete")
	}
	return nil
}
