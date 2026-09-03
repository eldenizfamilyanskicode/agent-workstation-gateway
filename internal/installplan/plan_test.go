package installplan

import (
	"bytes"
	"errors"
	"testing"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

func TestBuildWindowsPlanUsesOnlyFixedProtectedLayout(t *testing.T) {
	specification := validWindowsSpec()
	plan, err := Build(specification)
	if err != nil {
		t.Fatal(err)
	}
	expectedTargets := []string{
		`C:\ProgramData\AgentWorkstationGateway`,
		`C:\ProgramData\AgentWorkstationGateway\bin`,
		`C:\ProgramData\AgentWorkstationGateway\state`,
		`C:\ProgramData\AgentWorkstationGateway-runner`,
		`C:\ProgramData\AgentWorkstationGateway-runner\_work`,
		`C:\ProgramData\AgentWorkstationGateway-runner\responses`,
		`C:\Users\Alice\Projects`,
		`C:\ProgramData\AWGProfiles\Exec`,
		`C:\ProgramData\AWGTemp`,
		`C:\ProgramData\AgentWorkstationGateway\state\execution-credential.dpapi`,
		`C:\ProgramData\AgentWorkstationGateway\state\installation.json`,
	}
	if len(plan.Operations) != len(expectedTargets) {
		t.Fatalf("unexpected operation count: %d", len(plan.Operations))
	}
	for index, target := range expectedTargets {
		if plan.Operations[index].Target != target {
			t.Fatalf("operation %d target differs: %q", index, plan.Operations[index].Target)
		}
	}
	encoded, err := MarshalPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte("password"), []byte("secret"), []byte("identifier"), []byte("service_command")} {
		if bytes.Contains(bytes.ToLower(encoded), forbidden) {
			t.Fatal("dry-run plan exposed credential or authority input")
		}
	}
}

func TestWindowsLayoutDerivesOnlyFixedProtectedPaths(t *testing.T) {
	layout, err := WindowsLayout(`C:\ProgramData\AgentWorkstationGateway`)
	if err != nil {
		t.Fatal(err)
	}
	expected := Layout{
		Root:                    `C:\ProgramData\AgentWorkstationGateway`,
		BinDirectory:            `C:\ProgramData\AgentWorkstationGateway\bin`,
		StateDirectory:          `C:\ProgramData\AgentWorkstationGateway\state`,
		InstallationConfig:      `C:\ProgramData\AgentWorkstationGateway\state\installation.json`,
		ExecutionCredential:     `C:\ProgramData\AgentWorkstationGateway\state\execution-credential.dpapi`,
		RunnerRoot:              `C:\ProgramData\AgentWorkstationGateway-runner`,
		RunnerWorkDirectory:     `C:\ProgramData\AgentWorkstationGateway-runner\_work`,
		RunnerResponseDirectory: `C:\ProgramData\AgentWorkstationGateway-runner\responses`,
	}
	if layout != expected {
		t.Fatalf("unexpected layout: %#v", layout)
	}
}

func TestWindowsLayoutRejectsNoncanonicalOrFilesystemRoot(t *testing.T) {
	for _, root := range []string{`relative\AWG`, `c:\ProgramData\AWG`, `C:\`, `C:\ProgramData\..\AWG`} {
		if _, err := WindowsLayout(root); err == nil {
			t.Fatalf("invalid installation root was accepted: %q", root)
		}
	}
}

func TestDecodeWindowsSpecRejectsAuthorityFields(t *testing.T) {
	encoded := []byte(`{
		"config_version":1,"platform":"windows","installation_root":"C:\\ProgramData\\AgentWorkstationGateway",
		"control_account":"awg-control","execution_account":"awg-exec","approved_roots":["C:\\Users\\Alice\\Projects"],
		"shells":[{"shell":"pwsh","executable":"C:\\Program Files\\PowerShell\\7\\pwsh.exe"}],
		"profile_root":"C:\\ProgramData\\AWGProfiles\\Exec","temp_root":"C:\\ProgramData\\AWGTemp",
		"path_entries":["C:\\Windows\\System32"],"capabilities":[],"execution_sid":"S-1-5-18"}`)
	_, err := Decode(encoded)
	assertPlanError(t, err, "spec", "json-unknown-field")
}

func TestValidateWindowsSpecRejectsProtectedRootOverlap(t *testing.T) {
	tests := []struct {
		name  string
		alter func(*Spec)
		rule  string
	}{
		{name: "approved root", alter: func(spec *Spec) { spec.ApprovedRoots = []string{spec.InstallationRoot + `\projects`} }, rule: "overlaps-approved-root"},
		{name: "profile root", alter: func(spec *Spec) { spec.ProfileRoot = spec.InstallationRoot + `\profile` }, rule: "overlaps-profile-root"},
		{name: "temp root", alter: func(spec *Spec) { spec.TempRoot = spec.InstallationRoot + `\temp` }, rule: "overlaps-temp-root"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			specification := validWindowsSpec()
			test.alter(&specification)
			assertPlanError(t, Validate(specification), "installation_root", test.rule)
		})
	}
}

func TestValidateWindowsSpecRejectsDerivedRunnerRootOverlap(t *testing.T) {
	tests := []struct {
		name  string
		alter func(*Spec)
		field string
		rule  string
	}{
		{name: "approved root", alter: func(spec *Spec) { spec.ApprovedRoots = []string{spec.InstallationRoot + "-runner"} }, field: "installation_root", rule: "derived-runner-overlaps-approved-root"},
		{name: "profile root", alter: func(spec *Spec) { spec.ProfileRoot = spec.InstallationRoot + `-runner\profile` }, field: "installation_root", rule: "derived-runner-overlaps-profile-root"},
		{name: "temp root", alter: func(spec *Spec) { spec.TempRoot = spec.InstallationRoot + `-runner\temp` }, field: "installation_root", rule: "derived-runner-overlaps-temp-root"},
		{name: "shell", alter: func(spec *Spec) { spec.Shells[0].Executable = spec.InstallationRoot + `-runner\bin\pwsh.exe` }, field: "shells.executable", rule: "inside-derived-runner-root"},
		{name: "path", alter: func(spec *Spec) { spec.PathEntries[0] = spec.InstallationRoot + `-runner\bin` }, field: "path_entries", rule: "inside-derived-runner-root"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			specification := validWindowsSpec()
			test.alter(&specification)
			assertPlanError(t, Validate(specification), test.field, test.rule)
		})
	}
}

func TestBindAddsOnlyResolvedIdentityData(t *testing.T) {
	specification := validWindowsSpec()
	configuration, err := Bind(specification, IdentityBinding{
		ControlIdentifier: "S-1-5-21-2000-2000-2000-1001", ControlPrimaryGroupIdentifier: "S-1-5-32-545",
		ExecutionIdentifier: "S-1-5-21-2000-2000-2000-1002", ExecutionPrimaryGroupIdentifier: "S-1-5-32-545",
	})
	if err != nil {
		t.Fatal(err)
	}
	if configuration.ControlIdentity.Name != specification.ControlAccount ||
		configuration.ExecutionIdentity.Name != specification.ExecutionAccount ||
		configuration.ExecutionIdentity.Identifier == configuration.ControlIdentity.Identifier {
		t.Fatal("identity binding did not preserve the fixed accounts and distinct resolved SIDs")
	}
	if _, err := installconfig.MarshalCanonical(configuration); err != nil {
		t.Fatal(err)
	}
}

func validWindowsSpec() Spec {
	return Spec{
		ConfigVersion: installconfig.CurrentVersion, Platform: platformpath.Windows,
		InstallationRoot: `C:\ProgramData\AgentWorkstationGateway`, ControlAccount: "awg-control", ExecutionAccount: "awg-exec",
		ApprovedRoots: []string{`C:\Users\Alice\Projects`},
		Shells:        []installconfig.ShellBinding{{Shell: v1.ShellPwsh, Executable: `C:\Program Files\PowerShell\7\pwsh.exe`}},
		ProfileRoot:   `C:\ProgramData\AWGProfiles\Exec`, TempRoot: `C:\ProgramData\AWGTemp`,
		PathEntries: []string{`C:\Program Files\PowerShell\7`, `C:\Windows\System32`}, Capabilities: []installconfig.Capability{},
	}
}

func assertPlanError(t *testing.T, err error, field string, rule string) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Field != field || failure.Rule != rule {
		t.Fatalf("expected %s/%s, got %T / %v", field, rule, err, err)
	}
}
