//go:build windows

package process

import (
	"errors"
	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/protectedstate"
)

type credentialBlobReader interface {
	Read() ([]byte, error)
}

type protectedCredentialFile struct {
	path string
}

func (file protectedCredentialFile) Read() ([]byte, error) {
	protected, err := protectedstate.ReadExactFile(file.path, maxProtectedBlobBytes)
	if err != nil {
		return nil, boundaryError("credential-file-denied")
	}
	return protected, nil
}

func validateCredentialSecurityDescriptor(descriptor *windows.SECURITY_DESCRIPTOR) error {
	err := protectedstate.ValidateExactFileDescriptor(descriptor)
	if err == nil {
		return nil
	}
	var failure *protectedstate.Error
	if errors.As(err, &failure) {
		return boundaryError(failure.Rule)
	}
	return boundaryError("credential-acl-invalid")
}
