//go:build windows

package process

import (
	"errors"
	"strings"
	"unicode/utf16"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/protectedstate"
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
	err := protectedstate.ValidateFileDescriptor(descriptor)
	if err == nil {
		return nil
	}
	var failure *protectedstate.Error
	if errors.As(err, &failure) {
		return boundaryError(failure.Rule)
	}
	return boundaryError("credential-acl-invalid")
}
