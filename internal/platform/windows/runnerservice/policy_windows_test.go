//go:build windows

package runnerservice

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/brokerservice"
)

func TestBuildPlanFixesRunnerServiceAuthorityAndCommand(t *testing.T) {
	root := `C:\Program Data\Agent Workstation Gateway`
	plan, err := BuildPlan(root, "awg-control")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Name != Name || plan.Executable != root+`-runner\bin\RunnerService.exe` ||
		!reflect.DeepEqual(plan.Arguments, []string{Name}) ||
		!strings.Contains(plan.Command, `"C:\Program Data\Agent Workstation Gateway-runner\bin\RunnerService.exe"`) ||
		!strings.HasSuffix(plan.Command, " "+Name) {
		t.Fatalf("unexpected fixed runner service target: %#v", plan)
	}
	configuration := plan.Configuration
	if configuration.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS || configuration.StartType != mgr.StartAutomatic ||
		configuration.ErrorControl != mgr.ErrorNormal || configuration.BinaryPathName != plan.Command ||
		configuration.ServiceStartName != `.\awg-control` ||
		!reflect.DeepEqual(configuration.Dependencies, []string{brokerservice.Name}) ||
		configuration.Password != "" || configuration.DelayedAutoStart ||
		configuration.SidType != windows.SERVICE_SID_TYPE_NONE {
		t.Fatal("runner service configuration did not preserve the fixed control identity policy")
	}
	if stagedConfiguration(plan).StartType != mgr.StartDisabled {
		t.Fatal("runner service was not staged disabled")
	}
	if len(plan.RecoveryActions) != 3 || plan.RecoveryActions[0].Type != mgr.ServiceRestart ||
		plan.RecoveryActions[1].Type != mgr.ServiceRestart || plan.RecoveryActions[2].Type != mgr.NoAction {
		t.Fatal("runner service recovery is not bounded")
	}
	for _, action := range plan.RecoveryActions {
		if action.Type == mgr.RunCommand || action.Type == mgr.ComputerReboot {
			t.Fatal("runner recovery gained command or reboot authority")
		}
	}
}

func TestBuildPlanRejectsRootOrAccountAuthorityDrift(t *testing.T) {
	for _, test := range []struct{ root, account string }{
		{root: `relative\root`, account: "awg-control"},
		{root: `C:\ProgramData\AWG`, account: `DOMAIN\control`},
		{root: `C:\ProgramData\AWG`, account: "Administrator"},
	} {
		if _, err := BuildPlan(test.root, test.account); err == nil {
			t.Fatal("invalid runner service authority was accepted")
		}
	}
}

func TestInstalledRunnerServicePolicyRejectsDrift(t *testing.T) {
	plan, err := BuildPlan(`C:\ProgramData\AgentWorkstationGateway`, "awg-control")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateInstalledPolicy(plan, plan.Configuration, plan.RecoveryActions, plan.RecoveryResetPeriodSeconds, true, "", ""); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*mgr.Config)
	}{
		{name: "command", mutate: func(value *mgr.Config) { value.BinaryPathName += " --replace" }},
		{name: "account", mutate: func(value *mgr.Config) { value.ServiceStartName = "LocalSystem" }},
		{name: "dependency", mutate: func(value *mgr.Config) { value.Dependencies = nil }},
		{name: "password", mutate: func(value *mgr.Config) { value.Password = "exposed" }},
		{name: "start", mutate: func(value *mgr.Config) { value.StartType = mgr.StartManual }},
	} {
		t.Run(test.name, func(t *testing.T) {
			configuration := plan.Configuration
			configuration.Dependencies = append([]string(nil), plan.Configuration.Dependencies...)
			test.mutate(&configuration)
			assertServiceRule(t, validateInstalledPolicy(
				plan, configuration, plan.RecoveryActions, plan.RecoveryResetPeriodSeconds, true, "", "",
			), "service-configuration-mismatch")
		})
	}
}

func TestRunnerServiceSecurityDescriptorIsExact(t *testing.T) {
	for _, test := range []struct{ name, sddl, rule string }{
		{name: "accepted", sddl: ServiceSDDL},
		{name: "unprotected", sddl: "O:SYG:SYD:(A;;0xF01FF;;;SY)(A;;0xF01FF;;;BA)", rule: "service-dacl-not-protected"},
		{name: "control principal", sddl: "O:SYG:SYD:P(A;;0xF01FF;;;SY)(A;;0xF01FF;;;BA)(A;;0x10;;;AU)", rule: "service-dacl-not-exact"},
		{name: "weak system", sddl: "O:SYG:SYD:P(A;;0x10;;;SY)(A;;0xF01FF;;;BA)", rule: "service-ace-invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			descriptor, err := windows.SecurityDescriptorFromString(test.sddl)
			if err != nil {
				t.Fatal(err)
			}
			err = validateServiceDescriptor(descriptor)
			if test.rule == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			assertServiceRule(t, err, test.rule)
		})
	}
}

func assertServiceRule(t *testing.T, err error, rule string) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Rule != rule {
		t.Fatalf("expected %s, got %T / %v", rule, err, err)
	}
}
