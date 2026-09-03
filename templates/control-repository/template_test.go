package controltemplate

import (
	"strings"
	"testing"
)

const (
	testSourceSHA = "1111111111111111111111111111111111111111"
	testDigest    = "2222222222222222222222222222222222222222222222222222222222222222"
)

func TestRenderProducesInertPinnedPrivateControlFiles(t *testing.T) {
	files, err := Render(Config{
		GatewaySourceSHA:    testSourceSHA,
		ControlBinaryURL:    "https://github.com/eldenizfamilyanskicode/agent-workstation-gateway/releases/download/v0.1.0/awg-control-linux-amd64",
		ControlBinarySHA256: testDigest,
		InstallationRoot:    `C:\ProgramData\AgentWorkstationGateway`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || files[0].Path != ".github/workflows/execute-request.yml" || files[1].Path != "control-version.json" {
		t.Fatalf("unexpected rendered files: %#v", files)
	}
	workflow := string(files[0].Content)
	for _, required := range []string{
		"issues:", "types: [opened]", "runs-on: ubuntu-latest", "runs-on: [agent-workstation-gateway]",
		"permissions: {}", "contents: write", "actions: read", "--event \"$GITHUB_EVENT_PATH\"",
		`powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ". '{0}'"`,
		"actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
		"actions/download-artifact@018cc2cf5baa6db3ef3c5f8a56943fffe632ef53",
		`C:\ProgramData\AgentWorkstationGateway-runner\_awg\awg.exe`,
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("rendered workflow is missing %q", required)
		}
	}
	if strings.Contains(workflow, "actions/checkout") || strings.Contains(workflow, "__AWG_") ||
		strings.Contains(string(files[1].Content), "__AWG_") {
		t.Fatal("rendered template retained an unsafe workflow behavior or placeholder")
	}
}

func TestRenderRejectsUnpinnedOrUnsafeConfig(t *testing.T) {
	valid := Config{
		GatewaySourceSHA:    testSourceSHA,
		ControlBinaryURL:    "https://github.com/eldenizfamilyanskicode/agent-workstation-gateway/releases/download/v0.1.0/awg-control-linux-amd64",
		ControlBinarySHA256: testDigest,
		InstallationRoot:    `C:\ProgramData\AgentWorkstationGateway`,
	}
	cases := []Config{valid, valid, valid, valid}
	cases[0].GatewaySourceSHA = "main"
	cases[1].ControlBinaryURL = "https://example.com/awg-control"
	cases[2].ControlBinarySHA256 = "short"
	cases[3].InstallationRoot = `C:\ProgramData\Alice's Gateway`
	for _, config := range cases {
		if _, err := Render(config); err == nil {
			t.Fatalf("unsafe template config accepted: %#v", config)
		}
	}
}
