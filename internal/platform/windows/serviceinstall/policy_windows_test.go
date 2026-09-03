//go:build windows

package serviceinstall

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/brokerservice"
)

func TestBuildPlanFixesServiceAuthorityAndCommand(t *testing.T) {
	root := `C:\Program Data\Agent Workstation Gateway`
	plan, err := BuildPlan(root)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Name != brokerservice.Name || plan.Executable != root+`\bin\awg-broker.exe` ||
		!reflect.DeepEqual(plan.Arguments, []string{"--installation-root", root}) {
		t.Fatalf("unexpected fixed service target: %#v", plan)
	}
	if !strings.Contains(plan.Command, `"C:\Program Data\Agent Workstation Gateway\bin\awg-broker.exe"`) ||
		!strings.HasSuffix(plan.Command, `--installation-root "C:\Program Data\Agent Workstation Gateway"`) ||
		strings.Count(plan.Command, "--installation-root") != 1 {
		t.Fatalf("unexpected fixed service command: %q", plan.Command)
	}
	configuration := plan.Configuration
	if configuration.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS || configuration.StartType != mgr.StartAutomatic ||
		configuration.ErrorControl != mgr.ErrorNormal || configuration.BinaryPathName != plan.Command ||
		configuration.ServiceStartName != "LocalSystem" || len(configuration.Dependencies) != 0 ||
		configuration.DelayedAutoStart || configuration.SidType != windows.SERVICE_SID_TYPE_NONE {
		t.Fatal("service configuration did not preserve the fixed LocalSystem own-process policy")
	}
	if len(plan.RecoveryActions) != 3 || plan.RecoveryActions[0].Type != mgr.ServiceRestart ||
		plan.RecoveryActions[1].Type != mgr.ServiceRestart || plan.RecoveryActions[2].Type != mgr.NoAction ||
		!plan.RecoveryOnNonCrash || plan.RecoveryResetPeriodSeconds == 0 {
		t.Fatal("recovery policy was not bounded to two restarts and no action")
	}
	for _, action := range plan.RecoveryActions {
		if action.Type == mgr.RunCommand || action.Type == mgr.ComputerReboot {
			t.Fatal("service recovery gained command or reboot authority")
		}
	}
	staged := createConfiguration(plan)
	if staged.StartType != mgr.StartDisabled || staged.ServiceStartName != "LocalSystem" ||
		staged.BinaryPathName != plan.Command || staged.Description != "" || len(staged.Dependencies) != 0 {
		t.Fatal("create policy was not fixed, disabled, and otherwise equivalent to the final service")
	}
}

func TestBuildPlanRejectsInvalidRoot(t *testing.T) {
	for _, root := range []string{`relative\AWG`, `C:\`, `c:\ProgramData\AWG`} {
		_, err := BuildPlan(root)
		assertInstallRule(t, err, "installation-root-invalid")
	}
}

func TestInstalledPolicyVerificationRejectsDrift(t *testing.T) {
	plan, err := BuildPlan(`C:\ProgramData\AgentWorkstationGateway`)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateInstalledPolicy(
		plan, plan.Configuration, plan.RecoveryActions, plan.RecoveryResetPeriodSeconds,
		plan.RecoveryOnNonCrash, "", "",
	); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		config mgr.Config
		action []mgr.RecoveryAction
		reset  uint32
		flag   bool
		cmd    string
		reboot string
		rule   string
	}{
		{name: "binary", config: func() mgr.Config { value := plan.Configuration; value.BinaryPathName += " --unsafe"; return value }(), action: plan.RecoveryActions, reset: plan.RecoveryResetPeriodSeconds, flag: true, rule: "service-configuration-mismatch"},
		{name: "account", config: func() mgr.Config { value := plan.Configuration; value.ServiceStartName = "LocalService"; return value }(), action: plan.RecoveryActions, reset: plan.RecoveryResetPeriodSeconds, flag: true, rule: "service-configuration-mismatch"},
		{name: "dependency", config: func() mgr.Config { value := plan.Configuration; value.Dependencies = []string{"example"}; return value }(), action: plan.RecoveryActions, reset: plan.RecoveryResetPeriodSeconds, flag: true, rule: "service-configuration-mismatch"},
		{name: "recovery command", config: plan.Configuration, action: plan.RecoveryActions, reset: plan.RecoveryResetPeriodSeconds, flag: true, cmd: "example.exe", rule: "service-recovery-mismatch"},
		{name: "reboot", config: plan.Configuration, action: plan.RecoveryActions, reset: plan.RecoveryResetPeriodSeconds, flag: true, reboot: "example", rule: "service-recovery-mismatch"},
		{name: "unbounded restart", config: plan.Configuration, action: []mgr.RecoveryAction{{Type: mgr.ServiceRestart}}, reset: plan.RecoveryResetPeriodSeconds, flag: true, rule: "service-recovery-mismatch"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertInstallRule(t, validateInstalledPolicy(
				plan, test.config, test.action, test.reset, test.flag, test.cmd, test.reboot,
			), test.rule)
		})
	}
}

func TestServiceSecurityDescriptorIsExact(t *testing.T) {
	tests := []struct {
		name string
		sddl string
		rule string
	}{
		{name: "accepted", sddl: ServiceSDDL},
		{name: "administrator owner", sddl: "O:BAG:SYD:P(A;;0xF01FF;;;SY)(A;;0xF01FF;;;BA)", rule: "service-owner-mismatch"},
		{name: "administrator group", sddl: "O:SYG:BAD:P(A;;0xF01FF;;;SY)(A;;0xF01FF;;;BA)", rule: "service-group-mismatch"},
		{name: "unprotected", sddl: "O:SYG:SYD:(A;;0xF01FF;;;SY)(A;;0xF01FF;;;BA)", rule: "service-dacl-not-protected"},
		{name: "extra principal", sddl: "O:SYG:SYD:P(A;;0xF01FF;;;SY)(A;;0xF01FF;;;BA)(A;;0x4;;;WD)", rule: "service-dacl-not-exact"},
		{name: "insufficient rights", sddl: "O:SYG:SYD:P(A;;0x4;;;SY)(A;;0xF01FF;;;BA)", rule: "service-ace-invalid"},
		{name: "inheritable", sddl: "O:SYG:SYD:P(A;CI;0xF01FF;;;SY)(A;;0xF01FF;;;BA)", rule: "service-ace-invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor, err := windows.SecurityDescriptorFromString(test.sddl)
			if err != nil {
				t.Fatal("could not create synthetic service descriptor")
			}
			err = validateServiceDescriptor(descriptor)
			if test.rule == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			assertInstallRule(t, err, test.rule)
		})
	}
}

func assertInstallRule(t *testing.T, err error, rule string) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Rule != rule {
		t.Fatalf("expected %s, got %T / %v", rule, err, err)
	}
}
