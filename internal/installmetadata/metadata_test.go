package installmetadata

import (
	"strings"
	"testing"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

func TestMetadataRoundTrip(t *testing.T) {
	metadata := validMetadata()
	encoded, err := MarshalCanonical(metadata)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.ControlRepository != metadata.ControlRepository || len(decoded.ControlFiles) != 2 || !decoded.ControlFiles[0].Owned {
		t.Fatalf("metadata changed: %#v", decoded)
	}
}

func TestMetadataRejectsUnknownDuplicateAndAuthorityChanges(t *testing.T) {
	metadata := validMetadata()
	encoded, err := MarshalCanonical(metadata)
	if err != nil {
		t.Fatal(err)
	}
	for _, content := range [][]byte{
		[]byte(strings.Replace(string(encoded), `"metadata_version":1`, `"metadata_version":1,"unknown":true`, 1)),
		[]byte(strings.Replace(string(encoded), `"metadata_version":1`, `"metadata_version":1,"metadata_version":1`, 1)),
		append(encoded, []byte(` {}`)...),
	} {
		if _, err := Decode(content); err == nil {
			t.Fatal("non-strict metadata was accepted")
		}
	}
	metadata.ControlFiles[0].Path = "arbitrary"
	if err := Validate(metadata); err == nil {
		t.Fatal("arbitrary control path was accepted")
	}
}

func validMetadata() Metadata {
	return Metadata{
		MetadataVersion: Version, Platform: platformpath.Windows,
		InstallationRoot: `C:\ProgramData\AgentWorkstationGateway`, ControlRepository: "alice/example-control",
		RunnerName: "awg-windows-x64", GatewaySourceSHA: strings.Repeat("1", 40),
		ControlFiles: []ControlFile{
			{Path: ".github/workflows/execute-request.yml", SHA256: strings.Repeat("2", 64), Owned: true},
			{Path: "control-version.json", SHA256: strings.Repeat("3", 64), Owned: false},
		},
	}
}
