//go:build windows

package installstate

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	sharedstate "github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installstate"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/process"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/protectedstate"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

const maxProtectedStateFileBytes = 64 * 1024

type NativeStore struct{}

type DPAPISealer struct{}

type Error struct {
	Rule string
}

func (failure *Error) Error() string {
	return fmt.Sprintf("Windows install-state boundary failed: %s", failure.Rule)
}

var _ sharedstate.Store = NativeStore{}
var _ sharedstate.Sealer = DPAPISealer{}

func (DPAPISealer) Seal(password []byte) ([]byte, error) {
	return process.ProtectPassword(password)
}

func (NativeStore) EnsureProtectedDirectory(path string) error {
	_, err := createProtectedDirectory(path, false)
	return err
}

// CreateNewProtectedDirectory creates and verifies one protected directory
// without adopting or modifying an existing object. The created result stays
// true when creation succeeded but a later apply/verification step failed.
func (NativeStore) CreateNewProtectedDirectory(path string) (bool, error) {
	return createProtectedDirectory(path, true)
}

func createProtectedDirectory(path string, createNewOnly bool) (created bool, resultErr error) {
	if err := validatePath(path); err != nil {
		return false, err
	}
	descriptor, err := windows.SecurityDescriptorFromString(protectedstate.DirectorySDDL)
	if err != nil {
		return false, storeError("directory-descriptor-invalid")
	}
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, storeError("directory-path-invalid")
	}
	attributes := windows.SecurityAttributes{
		Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor,
	}
	if err := windows.CreateDirectory(pathPointer, &attributes); err != nil {
		if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return false, storeError("directory-create-failed")
		}
		if createNewOnly {
			return false, storeError("directory-already-exists")
		}
	} else {
		created = true
	}
	handle, err := openDirectory(path, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return created, err
	}
	defer windows.CloseHandle(handle)
	if err := applySecurityDescriptor(handle, descriptor); err != nil {
		return created, err
	}
	actual, err := windows.GetSecurityInfo(
		handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || protectedstate.ValidateExactDirectoryDescriptor(actual) != nil {
		return created, storeError("directory-acl-verification-failed")
	}
	return created, nil
}

func (NativeStore) WriteProtectedFile(path string, content []byte) error {
	_, err := writeProtectedFile(path, content, maxProtectedStateFileBytes, true, false)
	return err
}

// WriteNewProtectedFile atomically creates one protected state file without
// replacing an existing target.
func (NativeStore) WriteNewProtectedFile(path string, content []byte) (bool, error) {
	return writeProtectedFile(path, content, maxProtectedStateFileBytes, false, false)
}

// WriteNewProtectedExecutable atomically creates one protected executable
// without replacing an existing target.
func (NativeStore) WriteNewProtectedExecutable(path string, content []byte) (bool, error) {
	return writeProtectedFile(path, content, protectedstate.MaxProtectedExecutableBytes, false, true)
}

func (NativeStore) VerifyProtectedDirectory(path string) error {
	return validateProtectedDirectory(path)
}

func (NativeStore) RemoveProtectedStateFile(path string) error {
	return removeProtectedFile(path, maxProtectedStateFileBytes, false)
}

func (NativeStore) RemoveProtectedExecutable(path string) error {
	return removeProtectedFile(path, protectedstate.MaxProtectedExecutableBytes, true)
}

func (NativeStore) RemoveProtectedDirectory(path string) error {
	pointer, exists, err := existingPath(path)
	if err != nil || !exists {
		return err
	}
	if err := validateProtectedDirectory(path); err != nil {
		return err
	}
	if err := windows.RemoveDirectory(pointer); err != nil {
		return storeError("directory-remove-failed")
	}
	return nil
}

func writeProtectedFile(
	path string,
	content []byte,
	maximumBytes int,
	replace bool,
	executable bool,
) (created bool, resultErr error) {
	if err := validatePath(path); err != nil {
		return false, err
	}
	if len(content) == 0 || len(content) > maximumBytes {
		return false, storeError("file-content-invalid")
	}
	parent := filepath.Dir(path)
	if parent == path || !platformpath.Contains(platformpath.Windows, parent, path) {
		return false, storeError("file-parent-invalid")
	}
	if err := validateProtectedDirectory(parent); err != nil {
		return false, err
	}
	if replace {
		if err := validateReplaceTarget(path); err != nil {
			return false, err
		}
	} else if err := validateAbsentTarget(path); err != nil {
		return false, err
	}
	temporary, err := temporaryPath(path)
	if err != nil {
		return false, err
	}
	temporaryPointer, err := windows.UTF16PtrFromString(temporary)
	if err != nil {
		return false, storeError("temporary-path-invalid")
	}
	defer windows.DeleteFile(temporaryPointer)
	if err := createProtectedFile(temporaryPointer, content); err != nil {
		return false, err
	}
	targetPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, storeError("file-path-invalid")
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	if err := windows.MoveFileEx(
		temporaryPointer, targetPointer, flags,
	); err != nil {
		return false, storeError("file-commit-failed")
	}
	created = !replace
	if err := validateProtectedFile(path, uint64(len(content))); err != nil {
		return created, err
	}
	if executable {
		if err := protectedstate.ValidateExactExecutable(path, maximumBytes); err != nil {
			return created, storeError("executable-verification-failed")
		}
	} else if err := protectedstate.ValidateExactFile(path, maximumBytes); err != nil {
		return created, storeError("file-exact-verification-failed")
	}
	return created, nil
}

func createProtectedFile(path *uint16, content []byte) error {
	descriptor, err := windows.SecurityDescriptorFromString(protectedstate.FileSDDL)
	if err != nil {
		return storeError("file-descriptor-invalid")
	}
	attributes := windows.SecurityAttributes{
		Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor,
	}
	handle, err := windows.CreateFile(
		path, windows.GENERIC_WRITE|windows.READ_CONTROL, 0, &attributes, windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_WRITE_THROUGH, 0,
	)
	if err != nil {
		return storeError("temporary-file-create-failed")
	}
	closed := false
	defer func() {
		if !closed {
			_ = windows.CloseHandle(handle)
		}
	}()
	written := 0
	for written < len(content) {
		var count uint32
		if err := windows.WriteFile(handle, content[written:], &count, nil); err != nil || count == 0 {
			return storeError("temporary-file-write-failed")
		}
		written += int(count)
	}
	if err := windows.FlushFileBuffers(handle); err != nil {
		return storeError("temporary-file-flush-failed")
	}
	if err := windows.CloseHandle(handle); err != nil {
		return storeError("temporary-file-close-failed")
	}
	closed = true
	return nil
}

func validateProtectedDirectory(path string) error {
	handle, err := openDirectory(path, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	descriptor, err := windows.GetSecurityInfo(
		handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || protectedstate.ValidateExactDirectoryDescriptor(descriptor) != nil {
		return storeError("parent-directory-not-protected")
	}
	return nil
}

func validateProtectedFile(path string, expectedSize uint64) error {
	handle, information, err := openFile(path)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	size := uint64(information.FileSizeHigh)<<32 | uint64(information.FileSizeLow)
	if size != expectedSize {
		return storeError("file-size-verification-failed")
	}
	descriptor, err := windows.GetSecurityInfo(
		handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || protectedstate.ValidateExactFileDescriptor(descriptor) != nil {
		return storeError("file-acl-verification-failed")
	}
	return nil
}

func validateReplaceTarget(path string) error {
	handle, _, err := openFile(path)
	if err == nil {
		if err := windows.CloseHandle(handle); err != nil {
			return storeError("replace-target-close-failed")
		}
		return nil
	}
	var failure *Error
	if errors.As(err, &failure) && failure.Rule == "file-not-found" {
		return nil
	}
	return err
}

func validateAbsentTarget(path string) error {
	handle, _, err := openFile(path)
	if err == nil {
		if closeErr := windows.CloseHandle(handle); closeErr != nil {
			return storeError("create-target-close-failed")
		}
		return storeError("create-target-already-exists")
	}
	var failure *Error
	if errors.As(err, &failure) && failure.Rule == "file-not-found" {
		return nil
	}
	return err
}

func removeProtectedFile(path string, maximumBytes int, executable bool) error {
	pointer, exists, err := existingPath(path)
	if err != nil || !exists {
		return err
	}
	if executable {
		err = protectedstate.ValidateExactExecutable(path, maximumBytes)
	} else {
		err = protectedstate.ValidateExactFile(path, maximumBytes)
	}
	if err != nil {
		return storeError("remove-target-not-exact")
	}
	if err := windows.DeleteFile(pointer); err != nil {
		return storeError("file-remove-failed")
	}
	return nil
}

func existingPath(path string) (*uint16, bool, error) {
	if err := validatePath(path); err != nil {
		return nil, false, err
	}
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, false, storeError("path-invalid")
	}
	_, err = windows.GetFileAttributes(pointer)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return pointer, false, nil
	}
	if err != nil {
		return nil, false, storeError("path-query-failed")
	}
	return pointer, true, nil
}

func openDirectory(path string, access uint32) (windows.Handle, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, storeError("directory-path-invalid")
	}
	handle, err := windows.CreateFile(
		pointer, access, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0,
	)
	if err != nil {
		return 0, storeError("directory-open-failed")
	}
	if err := validateHandlePathAndType(handle, path, true); err != nil {
		_ = windows.CloseHandle(handle)
		return 0, err
	}
	return handle, nil
}

func openFile(path string) (windows.Handle, windows.ByHandleFileInformation, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, windows.ByHandleFileInformation{}, storeError("file-path-invalid")
	}
	handle, err := windows.CreateFile(
		pointer, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT, 0,
	)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return 0, windows.ByHandleFileInformation{}, storeError("file-not-found")
	}
	if err != nil {
		return 0, windows.ByHandleFileInformation{}, storeError("file-open-failed")
	}
	if err := validateHandlePathAndType(handle, path, false); err != nil {
		_ = windows.CloseHandle(handle)
		return 0, windows.ByHandleFileInformation{}, err
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		_ = windows.CloseHandle(handle)
		return 0, information, storeError("file-query-failed")
	}
	return handle, information, nil
}

func validateHandlePathAndType(handle windows.Handle, expected string, directory bool) error {
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return storeError("handle-query-failed")
	}
	isDirectory := information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if isDirectory != directory || information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return storeError("handle-type-denied")
	}
	final, err := finalPath(handle)
	if err != nil || !platformpath.Equal(platformpath.Windows, final, expected) {
		return storeError("handle-alias-rejected")
	}
	return nil
}

func finalPath(handle windows.Handle) (string, error) {
	buffer := make([]uint16, 512)
	for {
		length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
		if err != nil {
			return "", storeError("final-path-query-failed")
		}
		if length < uint32(len(buffer)) {
			path := string(utf16.Decode(buffer[:length]))
			if strings.HasPrefix(path, `\\?\UNC\`) {
				return "", storeError("unc-path-denied")
			}
			path = strings.TrimPrefix(path, `\\?\`)
			if len(path) >= 2 && path[1] == ':' && path[0] >= 'a' && path[0] <= 'z' {
				path = strings.ToUpper(path[:1]) + path[1:]
			}
			if err := validatePath(path); err != nil {
				return "", err
			}
			return path, nil
		}
		if length > platformpath.MaxPathBytes {
			return "", storeError("final-path-invalid")
		}
		buffer = make([]uint16, int(length)+1)
	}
}

func applySecurityDescriptor(handle windows.Handle, descriptor *windows.SECURITY_DESCRIPTOR) error {
	owner, _, ownerErr := descriptor.Owner()
	group, _, groupErr := descriptor.Group()
	dacl, _, daclErr := descriptor.DACL()
	if ownerErr != nil || groupErr != nil || daclErr != nil || owner == nil || group == nil || dacl == nil {
		return storeError("descriptor-parts-invalid")
	}
	information := windows.SECURITY_INFORMATION(
		windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION |
			windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION,
	)
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, information, owner, group, dacl, nil); err != nil {
		return storeError("descriptor-apply-failed")
	}
	return nil
}

func temporaryPath(target string) (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", storeError("temporary-name-failed")
	}
	path := target + ".tmp-" + hex.EncodeToString(random)
	if err := validatePath(path); err != nil {
		return "", storeError("temporary-path-invalid")
	}
	return path, nil
}

func validatePath(path string) error {
	if err := platformpath.ValidateAbsolute(platformpath.Windows, path); err != nil || platformpath.IsFilesystemRoot(platformpath.Windows, path) {
		return storeError("path-invalid")
	}
	return nil
}

func storeError(rule string) error {
	return &Error{Rule: rule}
}
