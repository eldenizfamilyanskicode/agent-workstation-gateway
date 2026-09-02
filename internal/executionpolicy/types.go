package executionpolicy

import (
	"context"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

type Resolver interface {
	ResolveWithin(context.Context, platformpath.Platform, string, []string) (Resolution, error)
}

type Resolution struct {
	RequestedPath    string
	WorkingDirectory string
	ApprovedRoot     string
}

type LaunchPlan struct {
	RequestID         string
	RequestDigest     string
	SessionID         string
	AttemptID         string
	ExecutionIdentity installconfig.Principal
	Shell             v1.Shell
	Executable        string
	WorkingDirectory  string
	ApprovedRoot      string
	Script            string
	TimeoutSeconds    int
	MaxOutputBytes    int
	Artifacts         []v1.ArtifactSelection
	Environment       []string
	Capabilities      []installconfig.Capability
}
