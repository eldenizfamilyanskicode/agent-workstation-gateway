//go:build windows

package brokeripc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/ipcframe"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

const (
	pipeBufferBytes = ipcframe.HeaderBytes + ipcframe.MaxFrameBytes
	pipeInstances   = 1
	retryInterval   = 10 * time.Millisecond

	brokerRevertFailureExitCode = 70
	waitPollMilliseconds        = 25

	pipeServerOpenMode = windows.PIPE_ACCESS_DUPLEX |
		windows.FILE_FLAG_FIRST_PIPE_INSTANCE |
		windows.FILE_FLAG_OVERLAPPED
	pipeMode = windows.PIPE_TYPE_MESSAGE |
		windows.PIPE_READMODE_MESSAGE |
		windows.PIPE_WAIT |
		windows.PIPE_REJECT_REMOTE_CLIENTS

	pipeFullAccess windows.ACCESS_MASK = windows.STANDARD_RIGHTS_REQUIRED |
		windows.SYNCHRONIZE | 0x1ff
	pipeClientAccess windows.ACCESS_MASK = (windows.FILE_GENERIC_READ |
		windows.FILE_GENERIC_WRITE) &^ windows.FILE_APPEND_DATA
)

var authenticationPreface = [...]byte{'A', 'W', 'G', 1}

var (
	advapi32                   = windows.NewLazySystemDLL("advapi32.dll")
	procImpersonateNamedClient = advapi32.NewProc("ImpersonateNamedPipeClient")
)

type serverNative struct {
	acceptMu sync.Mutex
	mu       sync.Mutex
	pending  windows.Handle
	closed   bool

	controlSID         *windows.SID
	executionSID       *windows.SID
	expectedControlSID *windows.SID
}

type connNative struct {
	readMu  sync.Mutex
	writeMu sync.Mutex
	mu      sync.Mutex
	handle  windows.Handle
	server  bool
	closed  bool
}

func newServerNative(configuration installconfig.Config) (*serverNative, error) {
	if configuration.Platform != platformpath.Windows || installconfig.Validate(configuration) != nil {
		return nil, ipcError("installed-configuration-invalid")
	}
	control, err := accountSID(configuration.ControlIdentity.Identifier, "control-sid-invalid")
	if err != nil {
		return nil, err
	}
	execution, err := accountSID(configuration.ExecutionIdentity.Identifier, "execution-sid-invalid")
	if err != nil {
		return nil, err
	}
	if control.Equals(execution) {
		return nil, ipcError("identity-separation-required")
	}
	server := &serverNative{
		controlSID: control, executionSID: execution, expectedControlSID: control,
	}
	handle, err := server.createPipe()
	if err != nil {
		return nil, err
	}
	server.pending = handle
	return server, nil
}

func (server *serverNative) accept(ctx context.Context) (*connNative, error) {
	if ctx == nil {
		return nil, ipcError("accept-context-invalid")
	}
	server.acceptMu.Lock()
	defer server.acceptMu.Unlock()

	handle, err := server.pendingHandle()
	if err != nil {
		return nil, err
	}
	if err := connectPipe(ctx, handle); err != nil {
		server.discardPending(handle)
		return nil, err
	}
	preface := make([]byte, len(authenticationPreface))
	count, readErr := readHandle(ctx, handle, preface)
	if readErr != nil || count != len(preface) {
		server.discardPending(handle)
		return nil, ipcError("authentication-preface-invalid")
	}
	if err := verifyPeer(handle, server.expectedControlSID); err != nil {
		server.discardPending(handle)
		return nil, err
	}
	if !bytes.Equal(preface, authenticationPreface[:]) {
		server.discardPending(handle)
		return nil, ipcError("authentication-preface-invalid")
	}
	if err := server.transferPending(handle); err != nil {
		return nil, err
	}
	return &connNative{handle: handle, server: true}, nil
}

func (server *serverNative) pendingHandle() (windows.Handle, error) {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.closed {
		return 0, ipcError("server-closed")
	}
	if server.pending == 0 {
		handle, err := server.createPipe()
		if err != nil {
			return 0, err
		}
		server.pending = handle
	}
	return server.pending, nil
}

func (server *serverNative) transferPending(handle windows.Handle) error {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.closed || server.pending != handle {
		return ipcError("server-closed")
	}
	server.pending = 0
	return nil
}

func (server *serverNative) discardPending(handle windows.Handle) {
	server.mu.Lock()
	owned := false
	if server.pending == handle {
		server.pending = 0
		owned = true
	}
	server.mu.Unlock()
	if !owned {
		return
	}
	_ = windows.DisconnectNamedPipe(handle)
	_ = windows.CloseHandle(handle)
}

func (server *serverNative) close() error {
	server.mu.Lock()
	if server.closed {
		server.mu.Unlock()
		return nil
	}
	server.closed = true
	handle := server.pending
	server.pending = 0
	server.mu.Unlock()
	if handle == 0 {
		return nil
	}
	_ = windows.CancelIoEx(handle, nil)
	_ = windows.DisconnectNamedPipe(handle)
	if err := windows.CloseHandle(handle); err != nil {
		return ipcError("server-close-failed")
	}
	return nil
}

func (server *serverNative) createPipe() (windows.Handle, error) {
	descriptor, err := pipeDescriptor(server.controlSID)
	if err != nil {
		return 0, err
	}
	name, err := windows.UTF16PtrFromString(Name)
	if err != nil {
		return 0, ipcError("pipe-name-invalid")
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	handle, err := windows.CreateNamedPipe(
		name,
		pipeServerOpenMode,
		pipeMode,
		pipeInstances,
		pipeBufferBytes,
		pipeBufferBytes,
		0,
		&attributes,
	)
	runtime.KeepAlive(descriptor)
	if err != nil {
		return 0, ipcCause("pipe-create-failed", err)
	}
	actual, err := windows.GetSecurityInfo(
		handle,
		windows.SE_KERNEL_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || validatePipeDescriptor(actual, server.controlSID, server.executionSID) != nil {
		_ = windows.CloseHandle(handle)
		return 0, ipcError("pipe-dacl-verification-failed")
	}
	return handle, nil
}

func dialNative(ctx context.Context) (*connNative, error) {
	if ctx == nil {
		return nil, ipcError("dial-context-invalid")
	}
	name, err := windows.UTF16PtrFromString(Name)
	if err != nil {
		return nil, ipcError("pipe-name-invalid")
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, ipcCause("dial-canceled", err)
		}
		handle, openErr := windows.CreateFile(
			name,
			uint32(pipeClientAccess),
			0,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION,
			0,
		)
		if openErr == nil {
			if err := writeAuthenticationPreface(ctx, handle); err != nil {
				_ = windows.CloseHandle(handle)
				return nil, err
			}
			return &connNative{handle: handle}, nil
		}
		if !errors.Is(openErr, windows.ERROR_PIPE_BUSY) && !errors.Is(openErr, windows.ERROR_FILE_NOT_FOUND) {
			return nil, ipcCause("dial-failed", openErr)
		}
		timer := time.NewTimer(retryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ipcCause("dial-canceled", ctx.Err())
		case <-timer.C:
		}
	}
}

func writeAuthenticationPreface(ctx context.Context, handle windows.Handle) error {
	count, err := writeHandle(ctx, handle, authenticationPreface[:])
	if err != nil || count != len(authenticationPreface) {
		return ipcError("authentication-preface-write-failed")
	}
	return nil
}

func connectPipe(ctx context.Context, handle windows.Handle) error {
	_, err := overlappedOperation(ctx, handle, func(overlapped *windows.Overlapped, _ *uint32) error {
		return windows.ConnectNamedPipe(handle, overlapped)
	})
	if errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		return nil
	}
	if err != nil {
		if ctx.Err() != nil {
			return ipcCause("accept-canceled", ctx.Err())
		}
		return ipcCause("accept-failed", err)
	}
	return nil
}

func (connection *connNative) read(ctx context.Context, buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	connection.readMu.Lock()
	defer connection.readMu.Unlock()
	handle, err := connection.openHandle()
	if err != nil {
		return 0, err
	}
	count, err := readHandle(ctx, handle, buffer)
	if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_NO_DATA) {
		return 0, io.EOF
	}
	if errors.Is(err, windows.ERROR_MORE_DATA) && count > 0 {
		return count, nil
	}
	if err != nil {
		if ctx.Err() != nil {
			return 0, ipcCause("read-canceled", ctx.Err())
		}
		return 0, ipcCause("read-failed", err)
	}
	return count, nil
}

func (connection *connNative) write(ctx context.Context, buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	connection.writeMu.Lock()
	defer connection.writeMu.Unlock()
	handle, err := connection.openHandle()
	if err != nil {
		return 0, err
	}
	count, err := writeHandle(ctx, handle, buffer)
	if err != nil {
		if ctx.Err() != nil {
			return 0, ipcCause("write-canceled", ctx.Err())
		}
		return 0, ipcCause("write-failed", err)
	}
	if count != len(buffer) {
		return count, io.ErrShortWrite
	}
	return count, nil
}

func (connection *connNative) openHandle() (windows.Handle, error) {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if connection.closed || connection.handle == 0 {
		return 0, ipcError("connection-closed")
	}
	return connection.handle, nil
}

func (connection *connNative) close() error {
	connection.mu.Lock()
	if connection.closed {
		connection.mu.Unlock()
		return nil
	}
	connection.closed = true
	handle := connection.handle
	connection.handle = 0
	server := connection.server
	connection.mu.Unlock()
	if handle == 0 {
		return nil
	}
	_ = windows.CancelIoEx(handle, nil)
	connection.readMu.Lock()
	defer connection.readMu.Unlock()
	connection.writeMu.Lock()
	defer connection.writeMu.Unlock()
	if server {
		_ = windows.DisconnectNamedPipe(handle)
	}
	if err := windows.CloseHandle(handle); err != nil {
		return ipcError("connection-close-failed")
	}
	return nil
}

func readHandle(ctx context.Context, handle windows.Handle, buffer []byte) (int, error) {
	return overlappedOperation(ctx, handle, func(overlapped *windows.Overlapped, done *uint32) error {
		return windows.ReadFile(handle, buffer, done, overlapped)
	})
}

func writeHandle(ctx context.Context, handle windows.Handle, buffer []byte) (int, error) {
	return overlappedOperation(ctx, handle, func(overlapped *windows.Overlapped, done *uint32) error {
		return windows.WriteFile(handle, buffer, done, overlapped)
	})
}

func overlappedOperation(
	ctx context.Context,
	handle windows.Handle,
	start func(*windows.Overlapped, *uint32) error,
) (int, error) {
	if ctx == nil {
		return 0, syscall.EINVAL
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(event)
	overlapped := windows.Overlapped{HEvent: event}
	var done uint32
	err = start(&overlapped, &done)
	if err == nil {
		return int(done), err
	}
	if errors.Is(err, windows.ERROR_MORE_DATA) {
		resultErr := windows.GetOverlappedResult(handle, &overlapped, &done, false)
		if resultErr == nil || errors.Is(resultErr, windows.ERROR_MORE_DATA) {
			return int(done), windows.ERROR_MORE_DATA
		}
		return int(done), resultErr
	}
	if !errors.Is(err, windows.ERROR_IO_PENDING) {
		return int(done), err
	}

	for {
		waitResult, waitErr := windows.WaitForSingleObject(event, waitPollMilliseconds)
		if waitErr != nil {
			_ = windows.CancelIoEx(handle, &overlapped)
			_ = windows.GetOverlappedResult(handle, &overlapped, &done, true)
			return int(done), waitErr
		}
		if waitResult == windows.WAIT_OBJECT_0 {
			err = windows.GetOverlappedResult(handle, &overlapped, &done, false)
			return int(done), err
		}
		if waitResult != uint32(windows.WAIT_TIMEOUT) {
			_ = windows.CancelIoEx(handle, &overlapped)
			_ = windows.GetOverlappedResult(handle, &overlapped, &done, true)
			return int(done), syscall.EINVAL
		}
		select {
		case <-ctx.Done():
			_ = windows.CancelIoEx(handle, &overlapped)
			_ = windows.GetOverlappedResult(handle, &overlapped, &done, true)
			return int(done), ctx.Err()
		default:
		}
	}
}

func verifyPeer(handle windows.Handle, expected *windows.SID) error {
	if expected == nil || !expected.IsValid() {
		return ipcError("expected-control-sid-invalid")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	result, _, callErr := procImpersonateNamedClient.Call(uintptr(handle))
	if result == 0 {
		return ipcCause("peer-impersonation-failed", callErr)
	}
	defer func() {
		if err := windows.RevertToSelf(); err != nil {
			// Continuing under a client token would convert an authentication
			// failure into privileged confused-deputy execution. ExitProcess is
			// the only safe recovery contract for this internal broker boundary.
			os.Exit(brokerRevertFailureExitCode)
		}
	}()
	var token windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token); err != nil {
		return ipcCause("peer-token-open-failed", err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return ipcError("peer-token-user-invalid")
	}
	if !user.User.Sid.Equals(expected) {
		return ipcError("peer-sid-mismatch")
	}
	return nil
}

func pipeDescriptor(control *windows.SID) (*windows.SECURITY_DESCRIPTOR, error) {
	if control == nil || !control.IsValid() {
		return nil, ipcError("control-sid-invalid")
	}
	sddl := "D:P" +
		"(A;;0x" + maskHex(pipeFullAccess) + ";;;SY)" +
		"(A;;0x" + maskHex(pipeFullAccess) + ";;;BA)" +
		"(A;;0x" + maskHex(pipeClientAccess) + ";;;" + control.String() + ")"
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, ipcError("pipe-descriptor-build-failed")
	}
	return descriptor, nil
}

func validatePipeDescriptor(descriptor *windows.SECURITY_DESCRIPTOR, control *windows.SID, execution *windows.SID) error {
	if descriptor == nil || control == nil || execution == nil || !control.IsValid() || !execution.IsValid() {
		return ipcError("pipe-descriptor-invalid")
	}
	descriptorControl, _, err := descriptor.Control()
	if err != nil || descriptorControl&windows.SE_DACL_PRESENT == 0 || descriptorControl&windows.SE_DACL_PROTECTED == 0 {
		return ipcError("pipe-dacl-not-protected")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 3 {
		return ipcError("pipe-dacl-not-exact")
	}
	foundSystem := false
	foundAdministrators := false
	foundControl := false
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil || ace == nil ||
			ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 ||
			ace.Header.AceSize < uint16(unsafe.Offsetof(ace.SidStart)+8) {
			return ipcError("pipe-ace-invalid")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || int(ace.Header.AceSize) < int(unsafe.Offsetof(ace.SidStart))+sid.Len() || sid.Equals(execution) {
			return ipcError("pipe-ace-principal-denied")
		}
		switch {
		case sid.IsWellKnown(windows.WinLocalSystemSid):
			if foundSystem || ace.Mask != pipeFullAccess {
				return ipcError("pipe-system-ace-invalid")
			}
			foundSystem = true
		case sid.IsWellKnown(windows.WinBuiltinAdministratorsSid):
			if foundAdministrators || ace.Mask != pipeFullAccess {
				return ipcError("pipe-administrators-ace-invalid")
			}
			foundAdministrators = true
		case sid.Equals(control):
			if foundControl || ace.Mask != pipeClientAccess || ace.Mask&windows.FILE_APPEND_DATA != 0 {
				return ipcError("pipe-control-ace-invalid")
			}
			foundControl = true
		default:
			return ipcError("pipe-ace-principal-denied")
		}
	}
	if !foundSystem || !foundAdministrators || !foundControl {
		return ipcError("pipe-dacl-incomplete")
	}
	return nil
}

func accountSID(value string, rule string) (*windows.SID, error) {
	if !strings.HasPrefix(strings.ToUpper(value), "S-1-5-21-") {
		return nil, ipcError(rule)
	}
	sid, err := windows.StringToSid(value)
	if err != nil || sid == nil || !sid.IsValid() {
		return nil, ipcError(rule)
	}
	return sid, nil
}

func maskHex(mask windows.ACCESS_MASK) string {
	return strconv.FormatUint(uint64(mask), 16)
}
