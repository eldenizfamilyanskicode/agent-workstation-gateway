package accountprovision

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

type fakeNative struct {
	exists     map[string]bool
	created    []string
	policies   []Role
	deleted    []string
	failCreate string
}

func (native *fakeNative) AccountExists(name string) (bool, error) { return native.exists[name], nil }
func (native *fakeNative) CreateAccount(name string, password []byte) (Account, error) {
	if name == native.failCreate {
		return Account{}, errors.New("synthetic")
	}
	native.created = append(native.created, name)
	identifier := "S-1-5-21-2000-2000-2000-1001"
	if len(native.created) == 2 {
		identifier = "S-1-5-21-2000-2000-2000-1002"
	}
	return Account{Name: name, Identifier: identifier, PrimaryGroupIdentifier: "S-1-5-32-545"}, nil
}
func (native *fakeNative) ApplyPolicy(role Role, _ Account) error {
	native.policies = append(native.policies, role)
	return nil
}
func (native *fakeNative) DeleteAccount(name string) error {
	native.deleted = append(native.deleted, name)
	return nil
}

type fixedGenerator struct {
	passwords [][]byte
}

func (generator *fixedGenerator) Generate() ([]byte, error) {
	password := generator.passwords[0]
	generator.passwords = generator.passwords[1:]
	return password, nil
}

func TestCryptoPasswordsMeetClassesAndDiffer(t *testing.T) {
	first, err := (CryptoPasswordGenerator{}).Generate()
	if err != nil {
		t.Fatal(err)
	}
	defer zeroBytes(first)
	second, err := (CryptoPasswordGenerator{}).Generate()
	if err != nil {
		t.Fatal(err)
	}
	defer zeroBytes(second)
	if len(first) != PasswordBytes || bytes.Equal(first, second) {
		t.Fatal("generated passwords have invalid length or repeated")
	}
	for _, class := range passwordClasses {
		if !containsAny(first, class) {
			t.Fatal("generated password omitted a required complexity class")
		}
	}
}

func TestProvisionBindsDistinctAccountsAndCommitClearsSecrets(t *testing.T) {
	native := &fakeNative{exists: make(map[string]bool)}
	control := []byte("Synthetic-control-password-1!")
	execution := []byte("Synthetic-execution-password-2!")
	lease, err := Provision(context.Background(), accountSpec(), native, &fixedGenerator{passwords: [][]byte{control, execution}})
	if err != nil {
		t.Fatal(err)
	}
	if len(native.created) != 2 || len(native.policies) != 2 || lease.Binding.ControlIdentifier == lease.Binding.ExecutionIdentifier {
		t.Fatal("account transaction did not bind two policy-converged identities")
	}
	if err := lease.Commit(); err != nil {
		t.Fatal(err)
	}
	if lease.ControlPassword() != nil || lease.ExecutionPassword() != nil || len(native.deleted) != 0 {
		t.Fatal("committed lease retained secrets or rolled accounts back")
	}
	assertZeroed(t, control)
	assertZeroed(t, execution)
}

func TestProvisionRollsBackOnlyCreatedAccountInReverseOrder(t *testing.T) {
	native := &fakeNative{exists: make(map[string]bool), failCreate: "awg-exec"}
	_, err := Provision(context.Background(), accountSpec(), native, &fixedGenerator{passwords: [][]byte{
		[]byte("Synthetic-control-password-3!"), []byte("Synthetic-execution-password-4!"),
	}})
	assertProvisionError(t, err, "execution-account-create-failed")
	if len(native.deleted) != 1 || native.deleted[0] != "awg-control" {
		t.Fatalf("rollback targets differ: %#v", native.deleted)
	}
}

func TestProvisionRejectsExistingAccountBeforePasswordGeneration(t *testing.T) {
	native := &fakeNative{exists: map[string]bool{"awg-control": true}}
	generator := &fixedGenerator{}
	_, err := Provision(context.Background(), accountSpec(), native, generator)
	assertProvisionError(t, err, "account-already-exists")
	if len(native.created) != 0 || len(native.deleted) != 0 {
		t.Fatal("pre-existing account reached create or rollback")
	}
}

func containsAny(password []byte, class []byte) bool {
	for _, value := range password {
		if bytes.ContainsRune(class, rune(value)) {
			return true
		}
	}
	return false
}

func assertZeroed(t *testing.T, buffer []byte) {
	t.Helper()
	for _, value := range buffer {
		if value != 0 {
			t.Fatal("password buffer was not cleared")
		}
	}
}

func accountSpec() installplan.Spec {
	return installplan.Spec{
		ConfigVersion: installconfig.CurrentVersion, Platform: platformpath.Windows,
		InstallationRoot: `C:\ProgramData\AgentWorkstationGateway`, ControlAccount: "awg-control", ExecutionAccount: "awg-exec",
		ApprovedRoots: []string{`C:\Users\Alice\Projects`},
		Shells:        []installconfig.ShellBinding{{Shell: v1.ShellPwsh, Executable: `C:\Program Files\PowerShell\7\pwsh.exe`}},
		ProfileRoot:   `C:\ProgramData\AWGProfiles\Exec`, TempRoot: `C:\ProgramData\AWGTemp`,
		PathEntries: []string{`C:\Windows\System32`}, Capabilities: []installconfig.Capability{},
	}
}

func assertProvisionError(t *testing.T, err error, rule string) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Rule != rule {
		t.Fatalf("expected %s, got %T / %v", rule, err, err)
	}
}
