//go:build windows

package account

import (
	"strings"
	"testing"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/accountprovision"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

func TestNativeAccountQueryForSyntheticMissingNameDoesNotMutate(t *testing.T) {
	specification := nativeAccountSpec()
	specification.ControlAccount = "awg-test-account-does-not-exist-74be"
	native, err := NewNative(specification)
	if err != nil {
		t.Fatal(err)
	}
	exists, err := native.AccountExists(specification.ControlAccount)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("synthetic missing account unexpectedly exists")
	}
}

func TestNativeRejectsAccountOutsideFixedSpecification(t *testing.T) {
	native, err := NewNative(nativeAccountSpec())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := native.AccountExists("request-selected"); err == nil {
		t.Fatal("native account boundary accepted a request-selected name")
	}
	if err := native.DeleteAccount(nativeAccountSpec().ControlAccount); err == nil {
		t.Fatal("native account boundary allowed deletion without same-transaction ownership")
	}
}

func TestFixedRoleRightsAreClosedAndMinimal(t *testing.T) {
	control, ok := fixedRights(accountprovision.RoleControl)
	if !ok || len(control) != 3 || !containsRight(control, "SeServiceLogonRight") || containsRight(control, "SeBatchLogonRight") {
		t.Fatalf("unexpected control rights: %#v", control)
	}
	execution, ok := fixedRights(accountprovision.RoleExecution)
	if !ok || len(execution) != 4 || !containsRight(execution, "SeBatchLogonRight") || containsRight(execution, "SeServiceLogonRight") {
		t.Fatalf("unexpected execution rights: %#v", execution)
	}
	if _, ok := fixedRights("request-selected"); ok {
		t.Fatal("unknown role selected native account rights")
	}
}

func TestMutablePasswordUTF16CanBeClearedWithoutEcho(t *testing.T) {
	password := []byte("Synthetic-π-password-51af!")
	encoded, err := mutableUTF16(password)
	if err != nil {
		t.Fatal(err)
	}
	if encoded[len(encoded)-1] != 0 {
		t.Fatal("native account password was not NUL terminated")
	}
	zeroUTF16(encoded)
	for _, value := range encoded {
		if value != 0 {
			t.Fatal("native account password buffer was not cleared")
		}
	}
}

func containsRight(rights []string, expected string) bool {
	for _, right := range rights {
		if strings.EqualFold(right, expected) {
			return true
		}
	}
	return false
}

func nativeAccountSpec() installplan.Spec {
	return installplan.Spec{
		ConfigVersion: installconfig.CurrentVersion, Platform: platformpath.Windows,
		InstallationRoot: `C:\ProgramData\AgentWorkstationGateway`, ControlAccount: "awg-control", ExecutionAccount: "awg-exec",
		ApprovedRoots: []string{`C:\Users\Alice\Projects`},
		Shells:        []installconfig.ShellBinding{{Shell: v1.ShellPwsh, Executable: `C:\Program Files\PowerShell\7\pwsh.exe`}},
		ProfileRoot:   `C:\ProgramData\AWGProfiles\Exec`, TempRoot: `C:\ProgramData\AWGTemp`,
		PathEntries: []string{`C:\Windows\System32`}, Capabilities: []installconfig.Capability{},
	}
}
