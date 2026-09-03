package installplan

import (
	"fmt"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

const MaxSpecBytes = 64 * 1024

type Spec struct {
	ConfigVersion    installconfig.Version        `json:"config_version"`
	Platform         platformpath.Platform        `json:"platform"`
	InstallationRoot string                       `json:"installation_root"`
	ControlAccount   string                       `json:"control_account"`
	ExecutionAccount string                       `json:"execution_account"`
	ApprovedRoots    []string                     `json:"approved_roots"`
	Shells           []installconfig.ShellBinding `json:"shells"`
	ProfileRoot      string                       `json:"profile_root"`
	TempRoot         string                       `json:"temp_root"`
	PathEntries      []string                     `json:"path_entries"`
	Capabilities     []installconfig.Capability   `json:"capabilities"`
}

type Layout struct {
	Root                    string `json:"root"`
	BinDirectory            string `json:"bin_directory"`
	BrokerExecutable        string `json:"broker_executable"`
	ControlExecutable       string `json:"control_executable"`
	StateDirectory          string `json:"state_directory"`
	InstallationConfig      string `json:"installation_config"`
	ExecutionCredential     string `json:"execution_credential"`
	RunnerRoot              string `json:"runner_root"`
	RunnerWorkDirectory     string `json:"runner_work_directory"`
	RunnerResponseDirectory string `json:"runner_response_directory"`
}

type Operation struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
}

type Plan struct {
	PlanVersion installconfig.Version `json:"plan_version"`
	Platform    platformpath.Platform `json:"platform"`
	Layout      Layout                `json:"layout"`
	Operations  []Operation           `json:"operations"`
}

type IdentityBinding struct {
	ControlIdentifier               string
	ControlPrimaryGroupIdentifier   string
	ExecutionIdentifier             string
	ExecutionPrimaryGroupIdentifier string
}

type Error struct {
	Field string
	Rule  string
}

func (failure *Error) Error() string {
	return fmt.Sprintf("installation plan validation failed for %s: %s", failure.Field, failure.Rule)
}

func planError(field string, rule string) error {
	return &Error{Field: field, Rule: rule}
}
