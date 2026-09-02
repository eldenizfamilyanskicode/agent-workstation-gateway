package installconfig

import (
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

type Version uint8

const CurrentVersion Version = 1

type Capability string

const (
	CapabilityDocker Capability = "docker"
)

type Config struct {
	ConfigVersion     Version               `json:"config_version"`
	Platform          platformpath.Platform `json:"platform"`
	ControlIdentity   Principal             `json:"control_identity"`
	ExecutionIdentity Principal             `json:"execution_identity"`
	ApprovedRoots     []string              `json:"approved_roots"`
	Shells            []ShellBinding        `json:"shells"`
	ProfileRoot       string                `json:"profile_root"`
	TempRoot          string                `json:"temp_root"`
	PathEntries       []string              `json:"path_entries"`
	Capabilities      []Capability          `json:"capabilities"`
}

type Principal struct {
	Name                   string `json:"name"`
	Identifier             string `json:"identifier"`
	PrimaryGroupIdentifier string `json:"primary_group_identifier"`
}

type ShellBinding struct {
	Shell      v1.Shell `json:"shell"`
	Executable string   `json:"executable"`
}
