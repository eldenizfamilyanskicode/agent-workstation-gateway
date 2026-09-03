//go:build windows

package protectedstate

import (
	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

func ValidateExactDirectory(path string) error {
	if platformpath.ValidateAbsolute(platformpath.Windows, path) != nil || platformpath.IsFilesystemRoot(platformpath.Windows, path) {
		return fileError("directory-policy-invalid")
	}
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fileError("directory-path-invalid")
	}
	handle, err := windows.CreateFile(
		pointer, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0,
	)
	if err != nil {
		return fileError("directory-open-failed")
	}
	defer windows.CloseHandle(handle)
	var information windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(handle, &information) != nil ||
		information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
		information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fileError("directory-shape-denied")
	}
	final, err := finalPath(handle)
	if err != nil || !platformpath.Equal(platformpath.Windows, final, path) {
		return fileError("directory-alias-rejected")
	}
	descriptor, err := windows.GetSecurityInfo(
		handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || ValidateExactDirectoryDescriptor(descriptor) != nil {
		return fileError("directory-protection-denied")
	}
	return nil
}
