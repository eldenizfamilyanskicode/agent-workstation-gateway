//go:build windows

package process

import (
	"runtime"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	maxPasswordBytes       = 1024
	maxProtectedBlobBytes  = 64 * 1024
	credentialProtectFlags = windows.CRYPTPROTECT_LOCAL_MACHINE | windows.CRYPTPROTECT_UI_FORBIDDEN
)

var credentialEntropy = []byte("agent-workstation-gateway/windows-execution-credential/v1")

// ProtectPassword seals a bounded UTF-8 password with machine-scoped DPAPI.
// The caller retains ownership of password and must clear it after this call.
// This package never persists the returned blob.
func ProtectPassword(password []byte) ([]byte, error) {
	if !validPassword(password) {
		return nil, boundaryError("credential-plaintext-invalid")
	}
	input := append([]byte(nil), password...)
	defer zeroBytes(input)

	protected, err := cryptProtect(input)
	if err != nil {
		return nil, boundaryError("credential-protect-failed")
	}
	return protected, nil
}

func unprotectPassword(protected []byte) ([]byte, error) {
	if len(protected) == 0 || len(protected) > maxProtectedBlobBytes {
		return nil, boundaryError("credential-blob-invalid")
	}
	input := append([]byte(nil), protected...)
	defer zeroBytes(input)

	plaintext, err := cryptUnprotect(input)
	if err != nil {
		return nil, boundaryError("credential-unprotect-failed")
	}
	if !validPassword(plaintext) {
		zeroBytes(plaintext)
		return nil, boundaryError("credential-plaintext-invalid")
	}
	return plaintext, nil
}

func cryptProtect(input []byte) ([]byte, error) {
	inputBlob := dataBlob(input)
	entropyBlob := dataBlob(credentialEntropy)
	var outputBlob windows.DataBlob
	if err := windows.CryptProtectData(
		&inputBlob, nil, &entropyBlob, 0, nil, credentialProtectFlags, &outputBlob,
	); err != nil {
		return nil, err
	}
	return copyAndFreeBlob(&outputBlob, maxProtectedBlobBytes)
}

func cryptUnprotect(input []byte) ([]byte, error) {
	inputBlob := dataBlob(input)
	entropyBlob := dataBlob(credentialEntropy)
	var outputBlob windows.DataBlob
	if err := windows.CryptUnprotectData(
		&inputBlob, nil, &entropyBlob, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &outputBlob,
	); err != nil {
		return nil, err
	}
	return copyAndFreeBlob(&outputBlob, maxPasswordBytes)
}

func dataBlob(data []byte) windows.DataBlob {
	return windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
}

func copyAndFreeBlob(blob *windows.DataBlob, limit int) ([]byte, error) {
	if blob.Data == nil || blob.Size == 0 || uint64(blob.Size) > uint64(limit) {
		freeBlob(blob)
		return nil, boundaryError("native-credential-output-invalid")
	}
	native := unsafe.Slice(blob.Data, int(blob.Size))
	result := append([]byte(nil), native...)
	freeBlob(blob)
	return result, nil
}

func freeBlob(blob *windows.DataBlob) {
	if blob.Data == nil {
		return
	}
	native := unsafe.Slice(blob.Data, int(blob.Size))
	zeroBytes(native)
	_, _ = windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(blob.Data))))
	blob.Data = nil
	blob.Size = 0
}

func validPassword(password []byte) bool {
	if len(password) == 0 || len(password) > maxPasswordBytes || !utf8.Valid(password) {
		return false
	}
	for _, value := range password {
		if value == 0 {
			return false
		}
	}
	return true
}

//go:noinline
func zeroBytes(buffer []byte) {
	for index := range buffer {
		buffer[index] = 0
	}
	runtime.KeepAlive(buffer)
}
