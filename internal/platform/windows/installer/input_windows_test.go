//go:build windows

package installer

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

const testSourceSHA = "0123456789abcdef0123456789abcdef01234567"

func TestPrepareInputPinsValidatedSpecificationAndBrokerImage(t *testing.T) {
	input := Input{Specification: installerSpec(), GatewaySourceSHA: testSourceSHA, BrokerImage: syntheticBrokerImage(testSourceSHA)}
	prepared, err := prepareInput(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Specification.ApprovedRoots[0] = "C:\\Mutated"
	input.BrokerImage[0] = 0
	if prepared.specification.ApprovedRoots[0] != "C:\\Users\\Alice\\Projects" || prepared.brokerImage[0] != 'M' {
		t.Fatal("validated installer input was not pinned against caller mutation")
	}
}

func TestPrepareInputRejectsEveryAuthorityInputBeforeMutation(t *testing.T) {
	valid := Input{Specification: installerSpec(), GatewaySourceSHA: testSourceSHA, BrokerImage: syntheticBrokerImage(testSourceSHA)}
	tests := []struct {
		name   string
		mutate func(*Input)
		rule   string
	}{
		{name: "specification", rule: "install-specification-invalid", mutate: func(input *Input) { input.Specification.InstallationRoot = "relative\\root" }},
		{name: "source sha", rule: "gateway-source-sha-invalid", mutate: func(input *Input) { input.GatewaySourceSHA = "refs/heads/main" }},
		{name: "empty image", rule: "broker-image-invalid", mutate: func(input *Input) { input.BrokerImage = nil }},
		{name: "wrong machine", rule: "broker-image-invalid", mutate: func(input *Input) { binary.LittleEndian.PutUint16(input.BrokerImage[0x84:0x86], 0x014c) }},
		{name: "dll", rule: "broker-image-invalid", mutate: func(input *Input) {
			binary.LittleEndian.PutUint16(input.BrokerImage[0x96:0x98], peExecutableImageFlag|peDLLFlag)
		}},
		{name: "missing embedded sha", rule: "broker-image-invalid", mutate: func(input *Input) { copy(input.BrokerImage[0xc0:], []byte("ffffffffffffffffffffffffffffffffffffffff")) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := Input{
				Specification: cloneSpecification(valid.Specification), GatewaySourceSHA: valid.GatewaySourceSHA,
				BrokerImage: append([]byte(nil), valid.BrokerImage...),
			}
			test.mutate(&input)
			_, err := prepareInput(input)
			assertInstallerRule(t, err, test.rule)
		})
	}
}

func TestBrokerImagePolicyAcceptsTheActualServiceBuild(t *testing.T) {
	target := filepath.Join(t.TempDir(), "awg-broker.exe")
	command := exec.Command(
		"go", "build", "-trimpath", "-ldflags=-X=main.gatewaySourceSHA="+testSourceSHA,
		"-o", target, "../../../../cmd/awg-broker",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("could not build actual broker fixture: %v / %s", err, output)
	}
	image, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !validBrokerImage(image, testSourceSHA) {
		t.Fatal("actual service-only broker build did not satisfy installer image policy")
	}
}

func syntheticBrokerImage(sourceSHA string) []byte {
	image := make([]byte, 256)
	image[0], image[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(image[peOffsetLocation:peOffsetLocation+4], 0x80)
	copy(image[0x80:0x84], []byte{'P', 'E', 0, 0})
	binary.LittleEndian.PutUint16(image[0x84:0x86], peMachineAMD64)
	binary.LittleEndian.PutUint16(image[0x86:0x88], 1)
	binary.LittleEndian.PutUint16(image[0x94:0x96], 0x20)
	binary.LittleEndian.PutUint16(image[0x96:0x98], peExecutableImageFlag)
	binary.LittleEndian.PutUint16(image[0x98:0x9a], peOptionalMagicPE32P)
	copy(image[0xc0:], []byte(sourceSHA))
	return image
}

func installerSpec() installplan.Spec {
	return installplan.Spec{
		ConfigVersion: installconfig.CurrentVersion, Platform: platformpath.Windows,
		InstallationRoot: "C:\\ProgramData\\AgentWorkstationGateway", ControlAccount: "awg-control", ExecutionAccount: "awg-exec",
		ApprovedRoots: []string{"C:\\Users\\Alice\\Projects"},
		Shells:        []installconfig.ShellBinding{{Shell: v1.ShellPwsh, Executable: "C:\\Program Files\\PowerShell\\7\\pwsh.exe"}},
		ProfileRoot:   "C:\\ProgramData\\AWGProfiles\\Exec", TempRoot: "C:\\ProgramData\\AWGTemp",
		PathEntries: []string{"C:\\Windows\\System32"}, Capabilities: []installconfig.Capability{},
	}
}

func assertInstallerRule(t *testing.T, err error, rule string) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Rule != rule {
		t.Fatalf("expected %s, got %T / %v", rule, err, err)
	}
}
