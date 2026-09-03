//go:build windows

package runnerstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/runnerpackage"
)

const (
	fullAccess           windows.ACCESS_MASK = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff
	directoryInheritance                     = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
)

type Lease struct {
	mu                 sync.Mutex
	layout             installplan.Layout
	controlSID         *windows.SID
	executionSID       *windows.SID
	ownedFiles         []string
	ownedFileKeys      map[string]struct{}
	ownedDirectories   []string
	ownedDirectoryKeys map[string]struct{}
	committed          bool
	closed             bool
}

type fileWriter struct {
	lease  *Lease
	handle windows.Handle
	path   string
	closed bool
}

type Error struct {
	Rule  string
	Cause error
}

func (failure *Error) Error() string {
	return fmt.Sprintf("Windows runner storage failed: %s", failure.Rule)
}

func (failure *Error) Unwrap() error { return failure.Cause }

func Provision(
	ctx context.Context,
	installationRoot string,
	controlIdentifier string,
	executionIdentifier string,
	image *runnerpackage.Image,
) (result *Lease, resultErr error) {
	if ctx == nil || image == nil || image.Version() == "" {
		return nil, storeError("dependency-required")
	}
	layout, err := installplan.WindowsLayout(installationRoot)
	if err != nil {
		return nil, storeError("installation-layout-invalid")
	}
	control, err := accountSID(controlIdentifier)
	if err != nil {
		return nil, storeError("control-sid-invalid")
	}
	execution, err := accountSID(executionIdentifier)
	if err != nil || execution.Equals(control) {
		return nil, storeError("execution-sid-invalid")
	}
	lease := &Lease{
		layout: layout, controlSID: control, executionSID: execution,
		ownedFileKeys: make(map[string]struct{}), ownedDirectoryKeys: make(map[string]struct{}),
	}
	failed := true
	defer func() {
		if failed {
			if rollbackErr := lease.Close(); rollbackErr != nil {
				result = nil
				resultErr = storeError("rollback-failed")
			}
		}
	}()
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := lease.createAbsoluteDirectoryLocked(layout.RunnerRoot, true); err != nil {
		return nil, err
	}
	if err := image.Extract(ctx, lease); err != nil {
		return nil, storeError("package-extraction-failed")
	}
	for _, directory := range []string{layout.RunnerWorkDirectory, layout.RunnerResponseDirectory} {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		if err := lease.createAbsoluteDirectory(directory); err != nil {
			return nil, storeError("runtime-directory-create-failed")
		}
	}
	failed = false
	return lease, nil
}

func (lease *Lease) CreateDirectory(relative string) error {
	if lease == nil {
		return storeError("lease-invalid")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return storeError("lease-closed")
	}
	path, err := lease.archivePath(relative)
	if err != nil {
		return err
	}
	return lease.createAbsoluteDirectoryLocked(path, false)
}

func (lease *Lease) CreateFile(relative string) (io.WriteCloser, error) {
	if lease == nil {
		return nil, storeError("lease-invalid")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return nil, storeError("lease-closed")
	}
	path, err := lease.archivePath(relative)
	if err != nil {
		return nil, err
	}
	parent := filepath.Dir(path)
	if _, owned := lease.ownedDirectoryKeys[fold(parent)]; !owned {
		return nil, storeError("file-parent-not-owned")
	}
	if err := validateObject(parent, true, lease.controlSID, lease.executionSID); err != nil {
		return nil, storeError("file-parent-changed")
	}
	descriptor, err := objectDescriptor(lease.controlSID, false)
	if err != nil {
		return nil, err
	}
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, storeError("file-path-invalid")
	}
	attributes := windows.SecurityAttributes{
		Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor,
	}
	handle, err := windows.CreateFile(
		pointer, windows.GENERIC_WRITE|windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER,
		0, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_WRITE_THROUGH, 0,
	)
	if err != nil {
		return nil, storeError("file-create-failed")
	}
	lease.ownedFiles = append(lease.ownedFiles, path)
	lease.ownedFileKeys[fold(path)] = struct{}{}
	if err := applyDescriptor(handle, descriptor); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	return &fileWriter{lease: lease, handle: handle, path: path}, nil
}

func (writer *fileWriter) Write(content []byte) (int, error) {
	if writer == nil || writer.closed || writer.handle == 0 {
		return 0, storeError("file-writer-closed")
	}
	var count uint32
	if err := windows.WriteFile(writer.handle, content, &count, nil); err != nil {
		return int(count), storeError("file-write-failed")
	}
	return int(count), nil
}

func (writer *fileWriter) Close() error {
	if writer == nil {
		return storeError("file-writer-invalid")
	}
	if writer.closed {
		return nil
	}
	writer.closed = true
	flushErr := windows.FlushFileBuffers(writer.handle)
	closeErr := windows.CloseHandle(writer.handle)
	writer.handle = 0
	if flushErr != nil || closeErr != nil {
		return storeError("file-close-failed")
	}
	writer.lease.mu.Lock()
	defer writer.lease.mu.Unlock()
	if writer.lease.closed || validateObject(writer.path, false, writer.lease.controlSID, writer.lease.executionSID) != nil {
		return storeError("file-verification-failed")
	}
	return nil
}

func (lease *Lease) Commit() error {
	if lease == nil {
		return storeError("lease-invalid")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return storeError("lease-closed")
	}
	lease.committed = true
	lease.closed = true
	lease.ownedFiles = nil
	lease.ownedFileKeys = nil
	lease.ownedDirectories = nil
	lease.ownedDirectoryKeys = nil
	return nil
}

func (lease *Lease) Close() error {
	if lease == nil {
		return nil
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return nil
	}
	lease.closed = true
	if lease.committed {
		return nil
	}
	failed := false
	for index := len(lease.ownedFiles) - 1; index >= 0; index-- {
		path := lease.ownedFiles[index]
		if objectMissing(path) {
			continue
		}
		if validateObject(path, false, lease.controlSID, lease.executionSID) != nil || removeFile(path) != nil {
			failed = true
		}
	}
	for index := len(lease.ownedDirectories) - 1; index >= 0; index-- {
		path := lease.ownedDirectories[index]
		if objectMissing(path) {
			continue
		}
		if validateObject(path, true, lease.controlSID, lease.executionSID) != nil || removeDirectory(path) != nil {
			failed = true
		}
	}
	lease.ownedFiles = nil
	lease.ownedFileKeys = nil
	lease.ownedDirectories = nil
	lease.ownedDirectoryKeys = nil
	if failed {
		return storeError("rollback-failed")
	}
	return nil
}

func (lease *Lease) Layout() (installplan.Layout, error) {
	if lease == nil {
		return installplan.Layout{}, storeError("lease-invalid")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return installplan.Layout{}, storeError("lease-closed")
	}
	return lease.layout, nil
}

// SealGeneratedState validates and takes rollback ownership of every object
// created beneath the exclusively create-owned runner root by the trusted
// runner configuration process. It replaces inherited ACLs with the exact
// protected runner policy before registration state can be consumed.
func (lease *Lease) SealGeneratedState(ctx context.Context) error {
	if lease == nil || ctx == nil {
		return storeError("dependency-required")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return storeError("lease-closed")
	}
	count := 0
	if err := lease.sealDirectoryLocked(ctx, lease.layout.RunnerRoot, &count); err != nil {
		return storeError("generated-state-denied")
	}
	return nil
}

// VerifyRegistrationState checks the fixed credential/configuration files
// produced by a successful GitHub runner repository registration. It does not
// parse or expose their secret content.
func (lease *Lease) VerifyRegistrationState(ctx context.Context) error {
	if lease == nil || ctx == nil {
		return storeError("dependency-required")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return storeError("lease-closed")
	}
	for _, name := range []string{".runner", ".credentials", ".credentials_rsaparams"} {
		if err := contextError(ctx); err != nil {
			return err
		}
		path := filepath.Join(lease.layout.RunnerRoot, name)
		if _, owned := lease.ownedFileKeys[fold(path)]; !owned ||
			validateObject(path, false, lease.controlSID, lease.executionSID) != nil {
			return storeError("registration-state-incomplete")
		}
	}
	return nil
}

// VerifyServiceExecutable revalidates the pinned runner service image through
// an exact no-share handle immediately before SCM registration.
func (lease *Lease) VerifyServiceExecutable(ctx context.Context) error {
	if lease == nil || ctx == nil {
		return storeError("dependency-required")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return storeError("lease-closed")
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	path := filepath.Join(lease.layout.RunnerRoot, "bin", "RunnerService.exe")
	if _, owned := lease.ownedFileKeys[fold(path)]; !owned ||
		validateObject(path, false, lease.controlSID, lease.executionSID) != nil {
		return storeError("runner-service-executable-invalid")
	}
	return nil
}

func (lease *Lease) sealDirectoryLocked(ctx context.Context, directory string, count *int) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return storeError("generated-directory-read-failed")
	}
	for _, entry := range entries {
		*count++
		if *count > runnerpackage.MaxEntries+1024 {
			return storeError("generated-entry-count-denied")
		}
		if err := contextError(ctx); err != nil {
			return err
		}
		path := filepath.Join(directory, entry.Name())
		if platformpath.ValidateAbsolute(platformpath.Windows, path) != nil ||
			!platformpath.Contains(platformpath.Windows, lease.layout.RunnerRoot, path) ||
			platformpath.Equal(platformpath.Windows, lease.layout.RunnerRoot, path) {
			return storeError("generated-path-denied")
		}
		information, err := entry.Info()
		if err != nil || (!information.IsDir() && !information.Mode().IsRegular()) {
			return storeError("generated-object-shape-denied")
		}
		directoryObject := information.IsDir()
		handle, err := openObject(path, directoryObject, windows.READ_CONTROL|windows.WRITE_DAC|windows.FILE_READ_ATTRIBUTES)
		if err != nil {
			return err
		}
		descriptor, descriptorErr := objectDescriptor(lease.controlSID, directoryObject)
		if descriptorErr == nil {
			descriptorErr = applyDescriptor(handle, descriptor)
		}
		if descriptorErr == nil {
			descriptorErr = validateHandleDescriptor(handle, directoryObject, lease.controlSID, lease.executionSID)
		}
		closeErr := windows.CloseHandle(handle)
		if descriptorErr != nil || closeErr != nil {
			return storeError("generated-object-seal-failed")
		}
		key := fold(path)
		if directoryObject {
			if _, owned := lease.ownedDirectoryKeys[key]; !owned {
				lease.ownedDirectories = append(lease.ownedDirectories, path)
				lease.ownedDirectoryKeys[key] = struct{}{}
			}
			if err := lease.sealDirectoryLocked(ctx, path, count); err != nil {
				return err
			}
			continue
		}
		if _, owned := lease.ownedFileKeys[key]; !owned {
			lease.ownedFiles = append(lease.ownedFiles, path)
			lease.ownedFileKeys[key] = struct{}{}
		}
	}
	return nil
}

func (lease *Lease) createAbsoluteDirectory(path string) error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return storeError("lease-closed")
	}
	return lease.createAbsoluteDirectoryLocked(path, false)
}

func (lease *Lease) createAbsoluteDirectoryLocked(path string, root bool) error {
	if platformpath.ValidateAbsolute(platformpath.Windows, path) != nil ||
		!platformpath.Contains(platformpath.Windows, lease.layout.RunnerRoot, path) {
		return storeError("directory-path-invalid")
	}
	if _, duplicate := lease.ownedDirectoryKeys[fold(path)]; duplicate {
		return storeError("directory-already-owned")
	}
	parent := filepath.Dir(path)
	if root {
		if err := validateParent(parent); err != nil {
			return err
		}
	} else {
		if _, owned := lease.ownedDirectoryKeys[fold(parent)]; !owned {
			return storeError("directory-parent-not-owned")
		}
		if err := validateObject(parent, true, lease.controlSID, lease.executionSID); err != nil {
			return storeError("directory-parent-changed")
		}
	}
	descriptor, err := objectDescriptor(lease.controlSID, true)
	if err != nil {
		return err
	}
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return storeError("directory-path-invalid")
	}
	attributes := windows.SecurityAttributes{
		Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor,
	}
	if err := windows.CreateDirectory(pointer, &attributes); err != nil {
		return storeCause("directory-create-failed", err)
	}
	lease.ownedDirectories = append(lease.ownedDirectories, path)
	lease.ownedDirectoryKeys[fold(path)] = struct{}{}
	handle, err := openObject(path, true, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	if err := applyDescriptor(handle, descriptor); err != nil {
		return err
	}
	if err := validateHandleDescriptor(handle, true, lease.controlSID, lease.executionSID); err != nil {
		return storeError("directory-verification-failed")
	}
	return nil
}

func (lease *Lease) archivePath(relative string) (string, error) {
	if relative == "" || strings.ContainsAny(relative, "\\:\x00") || strings.HasPrefix(relative, "/") {
		return "", storeError("archive-path-invalid")
	}
	segments := strings.Split(relative, "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return "", storeError("archive-path-invalid")
		}
	}
	path := filepath.Join(append([]string{lease.layout.RunnerRoot}, segments...)...)
	if platformpath.ValidateAbsolute(platformpath.Windows, path) != nil ||
		!platformpath.Contains(platformpath.Windows, lease.layout.RunnerRoot, path) ||
		platformpath.Equal(platformpath.Windows, lease.layout.RunnerRoot, path) {
		return "", storeError("archive-path-invalid")
	}
	return path, nil
}

func accountSID(identifier string) (*windows.SID, error) {
	if !strings.HasPrefix(identifier, "S-1-5-21-") {
		return nil, storeError("account-sid-invalid")
	}
	sid, err := windows.StringToSid(identifier)
	if err != nil || sid == nil || !sid.IsValid() {
		return nil, storeError("account-sid-invalid")
	}
	return sid, nil
}

func objectDescriptor(control *windows.SID, directory bool) (*windows.SECURITY_DESCRIPTOR, error) {
	flags := ""
	if directory {
		flags = "OICI"
	}
	sddl := fmt.Sprintf(
		"D:P(A;%s;0x%x;;;SY)(A;%s;0x%x;;;BA)(A;%s;0x%x;;;%s)",
		flags, fullAccess, flags, fullAccess, flags, fullAccess, control.String(),
	)
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, storeError("descriptor-build-failed")
	}
	return descriptor, nil
}

func applyDescriptor(handle windows.Handle, descriptor *windows.SECURITY_DESCRIPTOR) error {
	dacl, _, daclErr := descriptor.DACL()
	if daclErr != nil || dacl == nil {
		return storeError("descriptor-invalid")
	}
	information := windows.SECURITY_INFORMATION(
		windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION,
	)
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, information, nil, nil, dacl, nil); err != nil {
		return storeError("descriptor-apply-failed")
	}
	return nil
}

func validateParent(path string) error {
	handle, err := openObject(path, true, windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return storeError("runner-parent-unavailable")
	}
	return windows.CloseHandle(handle)
}

func validateObject(path string, directory bool, control *windows.SID, execution *windows.SID) error {
	handle, err := openObject(path, directory, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	return validateHandleDescriptor(handle, directory, control, execution)
}

func openObject(path string, directory bool, access uint32) (windows.Handle, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, storeError("object-path-invalid")
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(pointer, access, 0, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return 0, storeError("object-open-failed")
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		_ = windows.CloseHandle(handle)
		return 0, storeError("object-query-failed")
	}
	isDirectory := information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if isDirectory != directory || information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		(!directory && information.NumberOfLinks != 1) {
		_ = windows.CloseHandle(handle)
		return 0, storeError("object-shape-denied")
	}
	final, err := finalPath(handle)
	if err != nil || !platformpath.Equal(platformpath.Windows, final, path) {
		_ = windows.CloseHandle(handle)
		return 0, storeError("object-alias-denied")
	}
	return handle, nil
}

func validateHandleDescriptor(handle windows.Handle, directory bool, control *windows.SID, execution *windows.SID) error {
	descriptor, err := windows.GetSecurityInfo(
		handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil {
		return storeError("descriptor-query-failed")
	}
	owner, _, ownerErr := descriptor.Owner()
	flags, _, controlErr := descriptor.Control()
	if ownerErr != nil || controlErr != nil || owner == nil || owner.Equals(execution) ||
		flags&windows.SE_DACL_PRESENT == 0 || flags&windows.SE_DACL_PROTECTED == 0 {
		return storeError("descriptor-policy-denied")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 3 {
		return storeError("dacl-shape-denied")
	}
	seen := make(map[string]bool, 3)
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil ||
			ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceSize < uint16(unsafe.Offsetof(ace.SidStart)+8) || ace.Mask != fullAccess {
			return storeError("ace-policy-denied")
		}
		expectedFlags := uint8(0)
		if directory {
			expectedFlags = directoryInheritance
		}
		if ace.Header.AceFlags != expectedFlags {
			return storeError("ace-policy-denied")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || int(ace.Header.AceSize) < int(unsafe.Offsetof(ace.SidStart))+sid.Len() || sid.Equals(execution) {
			return storeError("ace-principal-denied")
		}
		key := ""
		switch {
		case sid.IsWellKnown(windows.WinLocalSystemSid):
			key = "system"
		case sid.IsWellKnown(windows.WinBuiltinAdministratorsSid):
			key = "administrators"
		case sid.Equals(control):
			key = "control"
		default:
			return storeError("ace-principal-denied")
		}
		if seen[key] {
			return storeError("ace-principal-denied")
		}
		seen[key] = true
	}
	if len(seen) != 3 {
		return storeError("principal-set-incomplete")
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
			value := string(utf16.Decode(buffer[:length]))
			if strings.HasPrefix(value, `\\?\UNC\`) {
				return "", storeError("unc-path-denied")
			}
			value = strings.TrimPrefix(value, `\\?\`)
			if len(value) >= 2 && value[1] == ':' && value[0] >= 'a' && value[0] <= 'z' {
				value = strings.ToUpper(value[:1]) + value[1:]
			}
			return value, nil
		}
		if length > platformpath.MaxPathBytes {
			return "", storeError("final-path-invalid")
		}
		buffer = make([]uint16, int(length)+1)
	}
}

func removeFile(path string) error {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil || windows.DeleteFile(pointer) != nil {
		return storeError("file-remove-failed")
	}
	return nil
}

func removeDirectory(path string) error {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil || windows.RemoveDirectory(pointer) != nil {
		return storeError("directory-remove-failed")
	}
	return nil
}

func objectMissing(path string) bool {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	_, err = windows.GetFileAttributes(pointer)
	return errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND)
}

func contextError(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return storeError("context-cancelled")
	default:
		return nil
	}
}

func fold(path string) string { return strings.ToLower(path) }

func storeError(rule string) error { return &Error{Rule: rule} }

func storeCause(rule string, cause error) error { return &Error{Rule: rule, Cause: cause} }

var _ runnerpackage.Store = (*Lease)(nil)
var _ io.WriteCloser = (*fileWriter)(nil)
