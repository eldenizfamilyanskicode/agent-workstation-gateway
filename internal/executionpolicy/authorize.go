package executionpolicy

import (
	"context"
	"strings"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/brokerproto"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/workloadenv"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

func Authorize(
	ctx context.Context,
	configuration installconfig.Config,
	envelope brokerproto.ExecuteEnvelope,
	safeBaseEnvironment []string,
	resolver Resolver,
) (LaunchPlan, error) {
	if err := installconfig.Validate(configuration); err != nil {
		return LaunchPlan{}, policyError("config", "invalid-installation-config")
	}
	if err := brokerproto.ValidateExecuteEnvelope(envelope); err != nil {
		return LaunchPlan{}, policyError("envelope", "invalid-execute-envelope")
	}
	if resolver == nil {
		return LaunchPlan{}, policyError("working_directory", "resolver-required")
	}

	request := envelope.AcceptedRequest.Request
	if !requestPathMatchesPlatform(configuration.Platform, request.WorkingDirectory) {
		return LaunchPlan{}, policyError("working_directory", "platform-mismatch")
	}
	executable, found := configuredShell(configuration.Shells, request.Shell)
	if !found {
		return LaunchPlan{}, policyError("shell", "not-configured")
	}

	roots := append([]string(nil), configuration.ApprovedRoots...)
	resolution, err := resolver.ResolveWithin(ctx, configuration.Platform, request.WorkingDirectory, roots)
	if err != nil {
		return LaunchPlan{}, policyError("working_directory", "resolution-denied")
	}
	if err := validateResolution(configuration, request.WorkingDirectory, resolution); err != nil {
		return LaunchPlan{}, err
	}

	environment, err := workloadenv.Build(configuration, safeBaseEnvironment, workloadenv.Context{
		RequestID: request.RequestID,
		SessionID: request.SessionID,
		AttemptID: envelope.AttemptID,
	})
	if err != nil {
		return LaunchPlan{}, policyError("environment", "construction-failed")
	}

	return LaunchPlan{
		RequestID:         request.RequestID,
		RequestDigest:     envelope.AcceptedRequest.RequestDigest,
		SessionID:         request.SessionID,
		AttemptID:         envelope.AttemptID,
		Operation:         request.Operation,
		ProcessID:         request.ProcessID,
		ExecutionIdentity: configuration.ExecutionIdentity,
		Shell:             request.Shell,
		Executable:        executable,
		WorkingDirectory:  resolution.WorkingDirectory,
		ApprovedRoot:      resolution.ApprovedRoot,
		Script:            request.Script,
		TimeoutSeconds:    request.TimeoutSeconds,
		MaxOutputBytes:    request.MaxOutputBytes,
		Artifacts:         cloneArtifactSelections(request.Artifacts),
		Environment:       append([]string(nil), environment...),
		Capabilities:      append([]installconfig.Capability(nil), configuration.Capabilities...),
	}, nil
}

func configuredShell(bindings []installconfig.ShellBinding, requested v1.Shell) (string, bool) {
	for _, binding := range bindings {
		if binding.Shell == requested {
			return binding.Executable, true
		}
	}
	return "", false
}

func requestPathMatchesPlatform(platform platformpath.Platform, requested string) bool {
	switch platform {
	case platformpath.Windows:
		return len(requested) >= 3 && ((requested[0] >= 'A' && requested[0] <= 'Z') || (requested[0] >= 'a' && requested[0] <= 'z')) && requested[1] == ':' && requested[2] == '\\'
	case platformpath.Linux:
		return strings.HasPrefix(requested, "/")
	default:
		return false
	}
}

func validateResolution(configuration installconfig.Config, requested string, resolution Resolution) error {
	if resolution.RequestedPath != requested {
		return policyError("working_directory", "resolver-request-mismatch")
	}
	if err := platformpath.ValidateAbsolute(configuration.Platform, resolution.WorkingDirectory); err != nil {
		return policyError("working_directory", "resolver-returned-invalid-path")
	}
	if err := platformpath.ValidateAbsolute(configuration.Platform, resolution.ApprovedRoot); err != nil {
		return policyError("approved_root", "resolver-returned-invalid-root")
	}
	rootConfigured := false
	for _, configuredRoot := range configuration.ApprovedRoots {
		if platformpath.Equal(configuration.Platform, configuredRoot, resolution.ApprovedRoot) {
			rootConfigured = true
			break
		}
	}
	if !rootConfigured {
		return policyError("approved_root", "not-configured")
	}
	if !platformpath.Contains(configuration.Platform, resolution.ApprovedRoot, resolution.WorkingDirectory) {
		return policyError("working_directory", "outside-approved-root")
	}
	return nil
}

func cloneArtifactSelections(selections []v1.ArtifactSelection) []v1.ArtifactSelection {
	cloned := make([]v1.ArtifactSelection, len(selections))
	for index, selection := range selections {
		cloned[index] = v1.ArtifactSelection{
			Name:  selection.Name,
			Paths: append([]string(nil), selection.Paths...),
		}
	}
	return cloned
}
