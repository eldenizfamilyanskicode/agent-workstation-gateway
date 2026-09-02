package installstate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

type recordingStore struct {
	operations []string
	contents   map[string][]byte
}

func (store *recordingStore) EnsureProtectedDirectory(path string) error {
	store.operations = append(store.operations, "directory:"+path)
	return nil
}

func (store *recordingStore) WriteProtectedFile(path string, content []byte) error {
	store.operations = append(store.operations, "file:"+path)
	store.contents[path] = append([]byte(nil), content...)
	return nil
}

type recordingSealer struct {
	observed []byte
}

func (sealer *recordingSealer) Seal(password []byte) ([]byte, error) {
	sealer.observed = password
	return []byte("synthetic-protected-blob"), nil
}

func TestMaterializeWritesCredentialThenCanonicalConfig(t *testing.T) {
	specification := materializeSpec()
	plan, err := installplan.Build(specification)
	if err != nil {
		t.Fatal(err)
	}
	store := &recordingStore{contents: make(map[string][]byte)}
	sealer := &recordingSealer{}
	password := []byte("Synthetic-only-password-62ae!")
	receipt, err := Materialize(context.Background(), specification, materializeBinding(), password, store, sealer)
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.CredentialWritten || !receipt.ConfigWritten || len(store.operations) != 5 {
		t.Fatalf("incomplete materialization: %#v / %#v", receipt, store.operations)
	}
	if store.operations[3] != "file:"+plan.Layout.ExecutionCredential || store.operations[4] != "file:"+plan.Layout.InstallationConfig {
		t.Fatal("installed configuration was not the final commit marker")
	}
	for _, value := range sealer.observed {
		if value != 0 {
			t.Fatal("materializer did not clear its plaintext password copy")
		}
	}
	var configuration installconfig.Config
	if err := json.Unmarshal(store.contents[plan.Layout.InstallationConfig], &configuration); err != nil {
		t.Fatal("materializer did not write canonical installed configuration")
	}
	if configuration.ExecutionIdentity.Identifier != materializeBinding().ExecutionIdentifier {
		t.Fatal("installed configuration is not bound to the resolved execution SID")
	}
	if bytes.Contains(store.contents[plan.Layout.ExecutionCredential], password) {
		t.Fatal("protected credential output contains plaintext")
	}
}

func TestMaterializeDoesNotClearCallerOwnedPassword(t *testing.T) {
	password := []byte("Synthetic-caller-owned-password-1d90!")
	expected := append([]byte(nil), password...)
	store := &recordingStore{contents: make(map[string][]byte)}
	_, err := Materialize(context.Background(), materializeSpec(), materializeBinding(), password, store, &recordingSealer{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(password, expected) {
		t.Fatal("materializer changed caller-owned password memory")
	}
	zeroBytes(password)
	zeroBytes(expected)
}

func TestMaterializeCancelledBeforeMutation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store := &recordingStore{contents: make(map[string][]byte)}
	_, err := Materialize(ctx, materializeSpec(), materializeBinding(), []byte("synthetic"), store, &recordingSealer{})
	assertStateError(t, err, "context-cancelled")
	if len(store.operations) != 0 {
		t.Fatal("cancelled materialization mutated state")
	}
}

func TestMaterializeRejectsInvalidPasswordBeforeMutation(t *testing.T) {
	tests := [][]byte{nil, bytes.Repeat([]byte{'x'}, MaxPasswordBytes+1), {'x', 0, 'y'}, {0xff}}
	for _, password := range tests {
		store := &recordingStore{contents: make(map[string][]byte)}
		sealer := &recordingSealer{}
		_, err := Materialize(context.Background(), materializeSpec(), materializeBinding(), password, store, sealer)
		assertStateError(t, err, "password-invalid")
		if len(store.operations) != 0 || sealer.observed != nil {
			t.Fatal("invalid password reached a state mutation or sealer")
		}
	}
}

func materializeSpec() installplan.Spec {
	return installplan.Spec{
		ConfigVersion: installconfig.CurrentVersion, Platform: platformpath.Windows,
		InstallationRoot: `C:\ProgramData\AgentWorkstationGateway`, ControlAccount: "awg-control", ExecutionAccount: "awg-exec",
		ApprovedRoots: []string{`C:\Users\Alice\Projects`},
		Shells:        []installconfig.ShellBinding{{Shell: v1.ShellPwsh, Executable: `C:\Program Files\PowerShell\7\pwsh.exe`}},
		ProfileRoot:   `C:\ProgramData\AWGProfiles\Exec`, TempRoot: `C:\ProgramData\AWGTemp`,
		PathEntries: []string{`C:\Windows\System32`}, Capabilities: []installconfig.Capability{},
	}
}

func materializeBinding() installplan.IdentityBinding {
	return installplan.IdentityBinding{
		ControlIdentifier: "S-1-5-21-2000-2000-2000-1001", ControlPrimaryGroupIdentifier: "S-1-5-32-545",
		ExecutionIdentifier: "S-1-5-21-2000-2000-2000-1002", ExecutionPrimaryGroupIdentifier: "S-1-5-32-545",
	}
}

func assertStateError(t *testing.T, err error, rule string) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Rule != rule {
		t.Fatalf("expected %s, got %T / %v", rule, err, err)
	}
}
