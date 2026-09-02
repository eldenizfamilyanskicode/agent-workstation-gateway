package filesystemprovision

import (
	"context"
	"errors"
	"testing"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

type fakeChange struct {
	name      string
	rolled    *[]string
	discarded bool
	fail      bool
}

func (change *fakeChange) Rollback() error {
	*change.rolled = append(*change.rolled, change.name)
	if change.fail {
		return errors.New("synthetic")
	}
	return nil
}

func (change *fakeChange) Discard() { change.discarded = true }

type fakeNative struct {
	operations     []string
	changes        []*fakeChange
	failAt         int
	rollbackFailAt int
	rolled         []string
}

func (native *fakeNative) ConvergeApprovedRoot(path string, identifier string) (Change, error) {
	return native.converge("approved:"+path+":"+identifier, false)
}

func (native *fakeNative) ConvergeIsolatedRoot(path string, identifier string) (Change, error) {
	return native.converge("isolated:"+path+":"+identifier, false)
}

func (native *fakeNative) converge(operation string, rollbackFails bool) (Change, error) {
	native.operations = append(native.operations, operation)
	if native.failAt > 0 && len(native.operations) == native.failAt {
		return nil, errors.New("synthetic")
	}
	change := &fakeChange{
		name: operation, rolled: &native.rolled,
		fail: rollbackFails || (native.rollbackFailAt > 0 && len(native.operations) == native.rollbackFailAt),
	}
	native.changes = append(native.changes, change)
	return change, nil
}

func TestProvisionSurfacesRollbackFailure(t *testing.T) {
	native := &fakeNative{failAt: 3, rollbackFailAt: 1}
	_, err := Provision(context.Background(), validConfig(), native)
	assertError(t, err, "rollback-failed")
	if len(native.rolled) != 2 {
		t.Fatal("rollback stopped after the first error")
	}
}

func TestProvisionUsesOnlyInstalledTargetsAndExecutionSID(t *testing.T) {
	native := &fakeNative{}
	lease, err := Provision(context.Background(), validConfig(), native)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"approved:C:\\Users\\Alice\\Projects:S-1-5-21-2000-2000-2000-1002",
		"isolated:C:\\ProgramData\\AWGProfiles\\Exec:S-1-5-21-2000-2000-2000-1002",
		"isolated:C:\\ProgramData\\AWGTemp:S-1-5-21-2000-2000-2000-1002",
	}
	if len(native.operations) != len(expected) {
		t.Fatalf("unexpected operation count: %d", len(native.operations))
	}
	for index := range expected {
		if native.operations[index] != expected[index] {
			t.Fatalf("operation %d differs: %q", index, native.operations[index])
		}
	}
	if err := lease.Commit(); err != nil {
		t.Fatal(err)
	}
	for _, change := range native.changes {
		if !change.discarded {
			t.Fatal("commit retained rollback state")
		}
	}
	if err := lease.Close(); err != nil || len(native.rolled) != 0 {
		t.Fatal("committed lease rolled filesystem changes back")
	}
}

func TestProvisionFailureRollsBackCompletedChangesInReverse(t *testing.T) {
	native := &fakeNative{failAt: 3}
	_, err := Provision(context.Background(), validConfig(), native)
	assertError(t, err, "isolated-root-convergence-failed")
	if len(native.rolled) != 2 || native.rolled[0] != native.operations[1] || native.rolled[1] != native.operations[0] {
		t.Fatalf("rollback order differs: %#v", native.rolled)
	}
	for _, change := range native.changes {
		if !change.discarded {
			t.Fatal("rollback retained native change state")
		}
	}
}

func TestProvisionRejectsInvalidConfigBeforeMutation(t *testing.T) {
	configuration := validConfig()
	configuration.ExecutionIdentity.Identifier = "S-1-5-18"
	configuration.ControlIdentity.Identifier = "S-1-5-18"
	native := &fakeNative{}
	_, err := Provision(context.Background(), configuration, native)
	assertError(t, err, "installed-configuration-invalid")
	if len(native.operations) != 0 {
		t.Fatal("invalid installed configuration reached native mutation")
	}
}

func validConfig() installconfig.Config {
	return installconfig.Config{
		ConfigVersion: installconfig.CurrentVersion, Platform: platformpath.Windows,
		ControlIdentity:   installconfig.Principal{Name: "awg-control", Identifier: "S-1-5-21-2000-2000-2000-1001", PrimaryGroupIdentifier: "S-1-5-32-545"},
		ExecutionIdentity: installconfig.Principal{Name: "awg-exec", Identifier: "S-1-5-21-2000-2000-2000-1002", PrimaryGroupIdentifier: "S-1-5-32-545"},
		ApprovedRoots:     []string{`C:\Users\Alice\Projects`},
		Shells:            []installconfig.ShellBinding{{Shell: v1.ShellPwsh, Executable: `C:\Program Files\PowerShell\7\pwsh.exe`}},
		ProfileRoot:       `C:\ProgramData\AWGProfiles\Exec`, TempRoot: `C:\ProgramData\AWGTemp`,
		PathEntries: []string{`C:\Windows\System32`}, Capabilities: []installconfig.Capability{},
	}
}

func assertError(t *testing.T, err error, rule string) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Rule != rule {
		t.Fatalf("expected %s, got %T / %v", rule, err, err)
	}
}
