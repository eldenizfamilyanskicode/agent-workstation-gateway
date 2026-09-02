//go:build windows

package process

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
)

type fixedCredentialReader struct {
	blob  []byte
	reads int
}

func (reader *fixedCredentialReader) Read() ([]byte, error) {
	reader.reads++
	return append([]byte(nil), reader.blob...), nil
}

func TestCredentialSecurityDescriptorRequiresNarrowProtectedReaders(t *testing.T) {
	tests := []struct {
		name string
		sddl string
		rule string
	}{
		{name: "accepted", sddl: "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)"},
		{name: "unprotected", sddl: "O:SYG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)", rule: "credential-acl-not-protected"},
		{name: "untrusted reader", sddl: "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)", rule: "credential-ace-principal-denied"},
		{name: "untrusted owner", sddl: "O:WDG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)", rule: "credential-owner-denied"},
		{name: "missing system", sddl: "O:BAG:SYD:P(A;;FA;;;BA)", rule: "credential-acl-readers-incomplete"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor, err := windows.SecurityDescriptorFromString(test.sddl)
			if err != nil {
				t.Fatal("could not create synthetic security descriptor")
			}
			err = validateCredentialSecurityDescriptor(descriptor)
			if test.rule == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			assertBoundaryRule(t, err, test.rule)
		})
	}
}

func TestFileTokenSourceRejectsRequestIdentityBeforeCredentialRead(t *testing.T) {
	expected := syntheticExecutionPrincipal()
	reader := &fixedCredentialReader{}
	source := syntheticTokenSource(t, expected, reader)
	requested := expected
	requested.Identifier = "S-1-5-21-1000-1000-1000-9999"
	_, err := source.Acquire(context.Background(), requested)
	assertBoundaryRule(t, err, "token-source-identity-mismatch")
	if reader.reads != 0 {
		t.Fatal("identity mismatch reached protected credential storage")
	}
}

func TestFileTokenSourceRejectsCancelledContextBeforeCredentialRead(t *testing.T) {
	expected := syntheticExecutionPrincipal()
	reader := &fixedCredentialReader{}
	source := syntheticTokenSource(t, expected, reader)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := source.Acquire(ctx, expected)
	assertBoundaryRule(t, err, "token-source-context-cancelled")
	if reader.reads != 0 {
		t.Fatal("cancelled acquisition reached protected credential storage")
	}
}

func TestProtectedCredentialFileRejectsOrdinaryUserOwnedFixture(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.dpapi")
	if err := os.WriteFile(path, []byte("synthetic-not-a-credential"), 0o600); err != nil {
		t.Fatal("could not create synthetic credential fixture")
	}
	content, err := (protectedCredentialFile{path: path}).Read()
	if content != nil {
		zeroBytes(content)
		t.Fatal("ordinary user-owned credential fixture was accepted")
	}
	if err == nil {
		t.Fatal("ordinary user-owned credential fixture was not denied")
	}
	if bytes.Contains([]byte(err.Error()), []byte(path)) {
		t.Fatal("credential file denial echoed the configured path")
	}
}

func TestNewFileTokenSourceValidatesFixedInputs(t *testing.T) {
	principal := syntheticExecutionPrincipal()
	if _, err := NewFileTokenSource(principal, `relative\credential.dpapi`); err == nil {
		t.Fatal("relative credential path was accepted")
	}
	principal.Name = "INVALID\\account"
	if _, err := NewFileTokenSource(principal, `C:\ProgramData\AWG\credential.dpapi`); err == nil {
		t.Fatal("invalid fixed account was accepted")
	}
}

func TestFileTokenSourceUsesOnlyBatchLogonWithoutEcho(t *testing.T) {
	password := []byte("Synthetic-only-password-c82e!")
	defer zeroBytes(password)
	protected, err := ProtectPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	reader := &fixedCredentialReader{blob: protected}
	expected := syntheticExecutionPrincipal()
	source := syntheticTokenSource(t, expected, reader)
	lease, err := source.Acquire(context.Background(), expected)
	if lease != nil {
		_ = lease.Close()
		t.Fatal("nonexistent synthetic account unexpectedly produced a token")
	}
	assertBoundaryRule(t, err, "execution-batch-logon-failed")
	if reader.reads != 1 {
		t.Fatal("token source did not perform exactly one credential read")
	}
	if bytes.Contains([]byte(err.Error()), password) || bytes.Contains([]byte(err.Error()), []byte(expected.Name)) {
		t.Fatal("batch logon failure echoed configured credential data")
	}
}

func TestPasswordUTF16SupportsUnicodeAndCanBeCleared(t *testing.T) {
	encoded, err := passwordUTF16([]byte("Synthetic-π-𐐷"))
	if err != nil {
		t.Fatal(err)
	}
	if encoded[len(encoded)-1] != 0 {
		t.Fatal("native password was not NUL terminated")
	}
	zeroUTF16(encoded)
	for _, value := range encoded {
		if value != 0 {
			t.Fatal("native password buffer was not cleared")
		}
	}
}

func syntheticTokenSource(t *testing.T, expected installconfig.Principal, reader credentialBlobReader) *FileTokenSource {
	t.Helper()
	account, err := windows.UTF16FromString(expected.Name)
	if err != nil {
		t.Fatal(err)
	}
	domain, err := windows.UTF16FromString(localAccountDomain)
	if err != nil {
		t.Fatal(err)
	}
	return &FileTokenSource{expected: expected, account: account, domain: domain, reader: reader}
}

func syntheticExecutionPrincipal() installconfig.Principal {
	return installconfig.Principal{
		Name: "awg-test-no-account", Identifier: "S-1-5-21-1000-1000-1000-9876", PrimaryGroupIdentifier: "S-1-5-32-545",
	}
}
