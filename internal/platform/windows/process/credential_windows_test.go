//go:build windows

package process

import (
	"bytes"
	"errors"
	"testing"
)

func TestMachineCredentialProtectionRoundTrip(t *testing.T) {
	password := []byte("Synthetic-only-password-7f12!")
	defer zeroBytes(password)
	protected, err := ProtectPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(protected, password) {
		t.Fatal("protected credential contains its plaintext input")
	}
	plaintext, err := unprotectPassword(protected)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, password) {
		zeroBytes(plaintext)
		t.Fatal("unprotected credential did not match its input")
	}
	zeroBytes(plaintext)
	for _, value := range plaintext {
		if value != 0 {
			t.Fatal("plaintext credential buffer was not cleared")
		}
	}
}

func TestMachineCredentialProtectionRejectsTampering(t *testing.T) {
	password := []byte("Synthetic-only-password-19ac!")
	defer zeroBytes(password)
	protected, err := ProtectPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	protected[len(protected)/2] ^= 0xff
	plaintext, err := unprotectPassword(protected)
	if plaintext != nil {
		zeroBytes(plaintext)
		t.Fatal("tampered credential returned plaintext")
	}
	assertBoundaryRule(t, err, "credential-unprotect-failed")
	if bytes.Contains([]byte(err.Error()), password) {
		t.Fatal("credential failure echoed plaintext")
	}
}

func TestMachineCredentialProtectionBoundsInputs(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		rule  string
	}{
		{name: "empty plaintext", input: nil, rule: "credential-plaintext-invalid"},
		{name: "oversized plaintext", input: bytes.Repeat([]byte{'x'}, maxPasswordBytes+1), rule: "credential-plaintext-invalid"},
		{name: "nul plaintext", input: []byte{'x', 0, 'y'}, rule: "credential-plaintext-invalid"},
		{name: "invalid utf8 plaintext", input: []byte{0xff}, rule: "credential-plaintext-invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ProtectPassword(test.input)
			assertBoundaryRule(t, err, test.rule)
		})
	}

	_, err := unprotectPassword(bytes.Repeat([]byte{'x'}, MaxProtectedCredentialBytes+1))
	assertBoundaryRule(t, err, "credential-blob-invalid")
}

func TestCredentialErrorsAreClosed(t *testing.T) {
	_, err := ProtectPassword(nil)
	var failure *Error
	if !errors.As(err, &failure) || failure.Rule == "" {
		t.Fatal("credential error did not use the closed boundary error type")
	}
}
