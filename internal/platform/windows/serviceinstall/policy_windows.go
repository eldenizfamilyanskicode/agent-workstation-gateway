//go:build windows

package serviceinstall

import (
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/brokerservice"
)

const (
	DisplayName       = "Agent Workstation Gateway Broker"
	Description       = "Runs bounded Agent Workstation Gateway workloads under the installed restricted identity."
	ServiceSDDL       = "O:SYG:SYD:P(A;;0xF01FF;;;SY)(A;;0xF01FF;;;BA)"
	recoveryResetSecs = 24 * 60 * 60
)

var recoveryActions = []mgr.RecoveryAction{
	{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
	{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	{Type: mgr.NoAction, Delay: 0},
}

type Plan struct {
	Name                       string
	Executable                 string
	Arguments                  []string
	Command                    string
	Configuration              mgr.Config
	RecoveryActions            []mgr.RecoveryAction
	RecoveryResetPeriodSeconds uint32
	RecoveryOnNonCrash         bool
	SecurityDescriptor         string
}

type Error struct {
	Rule string
}

func (failure *Error) Error() string {
	return fmt.Sprintf("Windows service installation failed: %s", failure.Rule)
}

func BuildPlan(installationRoot string) (Plan, error) {
	layout, err := installplan.WindowsLayout(installationRoot)
	if err != nil {
		return Plan{}, installError("installation-root-invalid")
	}
	executable := layout.BinDirectory + `\awg-broker.exe`
	arguments := []string{"--installation-root", installationRoot}
	command := syscall.EscapeArg(executable)
	for _, argument := range arguments {
		command += " " + syscall.EscapeArg(argument)
	}
	configuration := mgr.Config{
		ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, StartType: mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal, BinaryPathName: command, Dependencies: []string{},
		ServiceStartName: "LocalSystem", DisplayName: DisplayName, Description: Description,
		SidType: windows.SERVICE_SID_TYPE_NONE, DelayedAutoStart: false,
	}
	return Plan{
		Name: brokerservice.Name, Executable: executable, Arguments: arguments, Command: command,
		Configuration: configuration, RecoveryActions: append([]mgr.RecoveryAction(nil), recoveryActions...),
		RecoveryResetPeriodSeconds: recoveryResetSecs, RecoveryOnNonCrash: true,
		SecurityDescriptor: ServiceSDDL,
	}, nil
}

func createConfiguration(plan Plan) mgr.Config {
	configuration := plan.Configuration
	configuration.StartType = mgr.StartDisabled
	configuration.Description = ""
	configuration.DelayedAutoStart = false
	return configuration
}

func validateInstalledPolicy(
	plan Plan,
	configuration mgr.Config,
	actions []mgr.RecoveryAction,
	resetPeriod uint32,
	onNonCrash bool,
	recoveryCommand string,
	rebootMessage string,
) error {
	expected := plan.Configuration
	if configuration.ServiceType != expected.ServiceType || configuration.StartType != expected.StartType ||
		configuration.ErrorControl != expected.ErrorControl || configuration.BinaryPathName != expected.BinaryPathName ||
		configuration.LoadOrderGroup != "" || configuration.TagId != 0 || len(configuration.Dependencies) != 0 ||
		!strings.EqualFold(configuration.ServiceStartName, expected.ServiceStartName) ||
		configuration.DisplayName != expected.DisplayName || configuration.Description != expected.Description ||
		configuration.SidType != expected.SidType || configuration.DelayedAutoStart != expected.DelayedAutoStart {
		return installError("service-configuration-mismatch")
	}
	if len(actions) != len(plan.RecoveryActions) {
		return installError("service-recovery-mismatch")
	}
	for index := range actions {
		if actions[index] != plan.RecoveryActions[index] {
			return installError("service-recovery-mismatch")
		}
	}
	if resetPeriod != plan.RecoveryResetPeriodSeconds || onNonCrash != plan.RecoveryOnNonCrash ||
		recoveryCommand != "" || rebootMessage != "" {
		return installError("service-recovery-mismatch")
	}
	return nil
}

func validateServiceDescriptor(descriptor *windows.SECURITY_DESCRIPTOR) error {
	if descriptor == nil {
		return installError("service-security-invalid")
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.IsWellKnown(windows.WinLocalSystemSid) {
		return installError("service-owner-mismatch")
	}
	group, _, err := descriptor.Group()
	if err != nil || group == nil || !group.IsWellKnown(windows.WinLocalSystemSid) {
		return installError("service-group-mismatch")
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PRESENT == 0 || control&windows.SE_DACL_PROTECTED == 0 {
		return installError("service-dacl-not-protected")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 2 {
		return installError("service-dacl-not-exact")
	}
	system := false
	administrators := false
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, uint32(index), &ace) != nil || ace == nil ||
			ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 ||
			ace.Header.AceSize < uint16(unsafe.Offsetof(ace.SidStart)+8) || ace.Mask != windows.SERVICE_ALL_ACCESS {
			return installError("service-ace-invalid")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || int(ace.Header.AceSize) < int(unsafe.Offsetof(ace.SidStart))+sid.Len() {
			return installError("service-ace-invalid")
		}
		switch {
		case sid.IsWellKnown(windows.WinLocalSystemSid):
			system = true
		case sid.IsWellKnown(windows.WinBuiltinAdministratorsSid):
			administrators = true
		default:
			return installError("service-principal-denied")
		}
	}
	if !system || !administrators {
		return installError("service-dacl-incomplete")
	}
	return nil
}

func installError(rule string) error { return &Error{Rule: rule} }
