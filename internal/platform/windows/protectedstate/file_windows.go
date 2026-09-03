//go:build windows

package protectedstate

import (
	"runtime"
	"strings"
	"unicode/utf16"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

const (
	MaxProtectedFileBytes       = 1024 * 1024
	MaxProtectedExecutableBytes = 256 * 1024 * 1024
)

type fileSnapshot struct {
	attributes   uint32
	volumeSerial uint32
	sizeHigh     uint32
	sizeLow      uint32
	links        uint32
	indexHigh    uint32
	indexLow     uint32
	writeHigh    uint32
	writeLow     uint32
}

func ValidateExactFile(path string, maximumBytes int) error {
	handle, _, err := openExactFile(path, maximumBytes, MaxProtectedFileBytes, false)
	if err != nil {
		return err
	}
	if err := windows.CloseHandle(handle); err != nil {
		return fileError("file-close-failed")
	}
	return nil
}

// ValidateExactExecutable validates a protected executable without weakening
// the substantially smaller ceiling used when protected state is read.
func ValidateExactExecutable(path string, maximumBytes int) error {
	handle, _, err := openExactFile(path, maximumBytes, MaxProtectedExecutableBytes, false)
	if err != nil {
		return err
	}
	if err := windows.CloseHandle(handle); err != nil {
		return fileError("file-close-failed")
	}
	return nil
}

func ReadExactFile(path string, maximumBytes int) (content []byte, resultErr error) {
	handle, before, err := openExactFile(path, maximumBytes, MaxProtectedFileBytes, true)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := windows.CloseHandle(handle); err != nil {
			zero(content)
			content = nil
			resultErr = fileError("file-close-failed")
		}
	}()
	content = make([]byte, int(before.sizeLow))
	offset := 0
	for offset < len(content) {
		var count uint32
		if err := windows.ReadFile(handle, content[offset:], &count, nil); err != nil || count == 0 {
			zero(content)
			return nil, fileError("file-read-failed")
		}
		offset += int(count)
	}
	after, err := snapshot(handle, maximumBytes)
	if err != nil || after != before {
		zero(content)
		return nil, fileError("file-changed")
	}
	return content, nil
}

func openExactFile(path string, maximumBytes int, policyMaximum int, read bool) (windows.Handle, fileSnapshot, error) {
	if maximumBytes <= 0 || maximumBytes > policyMaximum ||
		platformpath.ValidateAbsolute(platformpath.Windows, path) != nil ||
		platformpath.IsFilesystemRoot(platformpath.Windows, path) {
		return 0, fileSnapshot{}, fileError("file-policy-invalid")
	}
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, fileSnapshot{}, fileError("file-path-invalid")
	}
	access := uint32(windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL)
	if read {
		access |= windows.GENERIC_READ
	}
	handle, err := windows.CreateFile(
		pointer,
		access,
		0,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_SEQUENTIAL_SCAN,
		0,
	)
	if err != nil {
		return 0, fileSnapshot{}, fileError("file-open-failed")
	}
	failed := true
	defer func() {
		if failed {
			_ = windows.CloseHandle(handle)
		}
	}()
	before, err := snapshot(handle, maximumBytes)
	if err != nil {
		return 0, fileSnapshot{}, err
	}
	final, err := finalPath(handle)
	if err != nil || !platformpath.Equal(platformpath.Windows, final, path) {
		return 0, fileSnapshot{}, fileError("file-alias-rejected")
	}
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || ValidateExactFileDescriptor(descriptor) != nil {
		return 0, fileSnapshot{}, fileError("file-protection-denied")
	}
	failed = false
	return handle, before, nil
}

func snapshot(handle windows.Handle, maximumBytes int) (fileSnapshot, error) {
	fileType, err := windows.GetFileType(handle)
	if err != nil || fileType != windows.FILE_TYPE_DISK {
		return fileSnapshot{}, fileError("file-type-denied")
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return fileSnapshot{}, fileError("file-query-failed")
	}
	if information.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
		information.FileSizeHigh != 0 || information.FileSizeLow == 0 ||
		uint64(information.FileSizeLow) > uint64(maximumBytes) {
		return fileSnapshot{}, fileError("file-shape-denied")
	}
	if information.NumberOfLinks != 1 {
		return fileSnapshot{}, fileError("file-link-denied")
	}
	return fileSnapshot{
		attributes: information.FileAttributes, volumeSerial: information.VolumeSerialNumber,
		sizeHigh: information.FileSizeHigh, sizeLow: information.FileSizeLow, links: information.NumberOfLinks,
		indexHigh: information.FileIndexHigh, indexLow: information.FileIndexLow,
		writeHigh: information.LastWriteTime.HighDateTime, writeLow: information.LastWriteTime.LowDateTime,
	}, nil
}

func finalPath(handle windows.Handle) (string, error) {
	buffer := make([]uint16, 512)
	for {
		length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
		if err != nil {
			return "", fileError("file-final-path-query-failed")
		}
		if length < uint32(len(buffer)) {
			path := string(utf16.Decode(buffer[:length]))
			if strings.HasPrefix(path, `\\?\UNC\`) {
				return "", fileError("file-unc-path-denied")
			}
			path = strings.TrimPrefix(path, `\\?\`)
			if len(path) >= 2 && path[1] == ':' && path[0] >= 'a' && path[0] <= 'z' {
				path = strings.ToUpper(path[:1]) + path[1:]
			}
			if platformpath.ValidateAbsolute(platformpath.Windows, path) != nil {
				return "", fileError("file-final-path-invalid")
			}
			return path, nil
		}
		if length > platformpath.MaxPathBytes {
			return "", fileError("file-final-path-invalid")
		}
		buffer = make([]uint16, int(length)+1)
	}
}

func fileError(rule string) error {
	return &Error{Rule: rule}
}

//go:noinline
func zero(content []byte) {
	for index := range content {
		content[index] = 0
	}
	runtime.KeepAlive(content)
}
