package controltemplate

import (
	"embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/sourceversion"
)

//go:embed .github/workflows/execute-request.yml control-version.json
var files embed.FS

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Config struct {
	GatewaySourceSHA    string
	ControlBinaryURL    string
	ControlBinarySHA256 string
	InstallationRoot    string
}

type RenderedFile struct {
	Path    string
	Content []byte
}

type Error struct {
	Rule string
}

func (failure *Error) Error() string {
	return fmt.Sprintf("control repository template failed: %s", failure.Rule)
}

func Render(config Config) ([]RenderedFile, error) {
	if !sourceversion.IsCanonicalGitSHA(config.GatewaySourceSHA) || !digestPattern.MatchString(config.ControlBinarySHA256) ||
		!validReleaseURL(config.ControlBinaryURL) ||
		platformpath.ValidateAbsolute(platformpath.Windows, config.InstallationRoot) != nil ||
		platformpath.IsFilesystemRoot(platformpath.Windows, config.InstallationRoot) || strings.Contains(config.InstallationRoot, "'") {
		return nil, templateError("config-invalid")
	}
	layout, err := installplan.WindowsLayout(config.InstallationRoot)
	if err != nil {
		return nil, templateError("config-invalid")
	}
	paths := []string{".github/workflows/execute-request.yml", "control-version.json"}
	result := make([]RenderedFile, 0, len(paths))
	for _, path := range paths {
		content, err := files.ReadFile(path)
		if err != nil {
			return nil, templateError("embedded-file-invalid")
		}
		installationRoot := config.InstallationRoot
		if path == "control-version.json" {
			encodedRoot, encodeErr := json.Marshal(config.InstallationRoot)
			if encodeErr != nil {
				return nil, templateError("metadata-invalid")
			}
			installationRoot = string(encodedRoot[1 : len(encodedRoot)-1])
		}
		replacements := map[string]string{
			"__AWG_SOURCE_SHA__":        config.GatewaySourceSHA,
			"__AWG_CONTROL_URL__":       config.ControlBinaryURL,
			"__AWG_CONTROL_SHA256__":    config.ControlBinarySHA256,
			"__AWG_INSTALLATION_ROOT__": installationRoot,
			"__AWG_RUNNER_CLIENT__":     layout.RunnerControlExecutable,
		}
		rendered := string(content)
		for placeholder, value := range replacements {
			rendered = strings.ReplaceAll(rendered, placeholder, value)
		}
		if strings.Contains(rendered, "__AWG_") {
			return nil, templateError("placeholder-unresolved")
		}
		if path == "control-version.json" && !json.Valid([]byte(rendered)) {
			return nil, templateError("metadata-invalid")
		}
		result = append(result, RenderedFile{Path: path, Content: []byte(rendered)})
	}
	return result, nil
}

func validReleaseURL(value string) bool {
	prefix := "https://github.com/eldenizfamilyanskicode/agent-workstation-gateway/releases/download/"
	return strings.HasPrefix(value, prefix) && len(value) > len(prefix) &&
		!strings.ContainsAny(value, "\r\n\t '`")
}

func templateError(rule string) error { return &Error{Rule: rule} }
