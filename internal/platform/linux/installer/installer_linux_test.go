//go:build linux

package installer

import (
	"strings"
	"testing"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

func TestExpectedUnitsRetainSecurityBoundary(t *testing.T) {
	layout, err := installplan.LinuxLayout("/opt/agent-workstation-gateway")
	if err != nil {
		t.Fatal(err)
	}
	specification := installplan.Spec{Platform: platformpath.Linux, InstallationRoot: layout.Root, ControlAccount: "awg-control",
		ProfileRoot: "/var/lib/awg-exec", TempRoot: "/var/tmp/awg-exec", ApprovedRoots: []string{"/srv/awg/projects"}}
	broker := ExpectedBrokerUnit(layout, specification)
	runner := ExpectedRunnerUnit(layout, specification.ControlAccount)
	for _, expected := range []string{"User=root", "NoNewPrivileges=true", "ProtectSystem=strict", "CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_KILL CAP_CHOWN", "ReadWritePaths=/run/agent-workstation-gateway"} {
		if !strings.Contains(broker, expected) {
			t.Fatalf("broker unit is missing %q", expected)
		}
	}
	for _, expected := range []string{"User=awg-control", "Group=awg-control", "NoNewPrivileges=true", "ProtectSystem=strict", "WorkingDirectory=/opt/agent-workstation-gateway-runner"} {
		if !strings.Contains(runner, expected) {
			t.Fatalf("runner unit is missing %q", expected)
		}
	}
}
