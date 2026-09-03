package installmetadata

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/runnerregistration"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/sourceversion"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/strictjson"
)

const (
	Version  = 1
	MaxBytes = 32 * 1024
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var runnerNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type Metadata struct {
	MetadataVersion   int                   `json:"metadata_version"`
	Platform          platformpath.Platform `json:"platform"`
	InstallationRoot  string                `json:"installation_root"`
	ControlRepository string                `json:"control_repository"`
	RunnerName        string                `json:"runner_name"`
	GatewaySourceSHA  string                `json:"gateway_source_sha"`
	ControlFiles      []ControlFile         `json:"control_files"`
}

type ControlFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Owned  bool   `json:"owned"`
}

type Error struct {
	Rule string
}

func (failure *Error) Error() string {
	return fmt.Sprintf("installation metadata invalid: %s", failure.Rule)
}

func Validate(metadata Metadata) error {
	if metadata.MetadataVersion != Version || metadata.Platform != platformpath.Windows ||
		platformpath.ValidateAbsolute(platformpath.Windows, metadata.InstallationRoot) != nil ||
		platformpath.IsFilesystemRoot(platformpath.Windows, metadata.InstallationRoot) ||
		!sourceversion.IsCanonicalGitSHA(metadata.GatewaySourceSHA) {
		return metadataError("identity-invalid")
	}
	if _, err := runnerregistration.VerifyPrivateRepository(metadata.ControlRepository, true); err != nil {
		return metadataError("repository-invalid")
	}
	if len(metadata.RunnerName) > runnerregistration.MaxRunnerNameBytes || !runnerNamePattern.MatchString(metadata.RunnerName) ||
		metadata.RunnerName == "." || metadata.RunnerName == ".." {
		return metadataError("runner-name-invalid")
	}
	if len(metadata.ControlFiles) != 2 || metadata.ControlFiles[0].Path != ".github/workflows/execute-request.yml" ||
		metadata.ControlFiles[1].Path != "control-version.json" {
		return metadataError("control-files-invalid")
	}
	for _, file := range metadata.ControlFiles {
		if !digestPattern.MatchString(file.SHA256) {
			return metadataError("control-file-digest-invalid")
		}
	}
	return nil
}

func MarshalCanonical(metadata Metadata) ([]byte, error) {
	if err := Validate(metadata); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(metadata)
	if err != nil || len(encoded) > MaxBytes {
		return nil, metadataError("encode-failed")
	}
	return encoded, nil
}

func Decode(encoded []byte) (Metadata, error) {
	if len(encoded) == 0 || len(encoded) > MaxBytes {
		return Metadata{}, metadataError("encoded-size-invalid")
	}
	var metadata Metadata
	if err := strictjson.DecodeObject(encoded, MaxBytes, &metadata); err != nil {
		return Metadata{}, metadataError("decode-failed")
	}
	if err := Validate(metadata); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

func metadataError(rule string) error { return &Error{Rule: rule} }
