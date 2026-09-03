//go:build windows

package doctor

import (
	"context"
	"fmt"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installmetadata"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/account"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/filesystem"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/protectedstate"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/runnerservice"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/runnerstore"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/servicectl"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/serviceinstall"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/sourceversion"
)

type Report struct {
	Version                   string `json:"version"`
	SourceSHA                 string `json:"source_sha"`
	ProtectedState            bool   `json:"protected_state"`
	Identities                bool   `json:"identities"`
	FilesystemPolicy          bool   `json:"filesystem_policy"`
	RunnerState               bool   `json:"runner_state"`
	ServicePolicy             bool   `json:"service_policy"`
	ServicesRunning           bool   `json:"services_running"`
	PrivateRepository         bool   `json:"private_repository"`
	ExclusiveReaders          bool   `json:"exclusive_readers"`
	ExecutionCredentialDenied bool   `json:"execution_credential_acl_denies"`
	RunnerCredentialsDenied   bool   `json:"runner_credentials_acl_denies"`
}

type Installation struct {
	Configuration installconfig.Config
	Metadata      installmetadata.Metadata
}

type Error struct{ Rule string }

func (failure *Error) Error() string { return fmt.Sprintf("Windows doctor failed: %s", failure.Rule) }

func CheckLocal(ctx context.Context, installationRoot string, gatewaySourceSHA string) (Report, Installation, error) {
	report, installation, err := InspectInstalled(ctx, installationRoot, gatewaySourceSHA)
	if err != nil {
		return Report{}, Installation{}, err
	}
	status, err := servicectl.Inspect(ctx)
	if err != nil || !status.BrokerRunning || !status.RunnerRunning {
		return Report{}, Installation{}, doctorError("services-not-running")
	}
	report.ServicesRunning = true
	return report, installation, nil
}

func InspectInstalled(ctx context.Context, installationRoot string, gatewaySourceSHA string) (Report, Installation, error) {
	if ctx == nil || !sourceversion.IsCanonicalGitSHA(gatewaySourceSHA) {
		return Report{}, Installation{}, doctorError("input-invalid")
	}
	layout, err := installplan.WindowsLayout(installationRoot)
	if err != nil {
		return Report{}, Installation{}, doctorError("installation-root-invalid")
	}
	for _, path := range []string{layout.Root, layout.BinDirectory, layout.StateDirectory} {
		if protectedstate.ValidateExactDirectory(path) != nil {
			return Report{}, Installation{}, doctorError("protected-directory-invalid")
		}
	}
	for path, maximum := range map[string]int{
		layout.InstallationConfig:   installconfig.MaxConfigBytes,
		layout.InstallationMetadata: installmetadata.MaxBytes,
		layout.ExecutionCredential:  protectedstate.MaxProtectedFileBytes,
	} {
		if protectedstate.ValidateExactFile(path, maximum) != nil {
			return Report{}, Installation{}, doctorError("protected-file-invalid")
		}
	}
	for _, path := range []string{layout.BrokerExecutable, layout.ControlExecutable} {
		if protectedstate.ValidateExactExecutable(path, protectedstate.MaxProtectedExecutableBytes) != nil {
			return Report{}, Installation{}, doctorError("protected-executable-invalid")
		}
	}
	configBytes, err := protectedstate.ReadExactFile(layout.InstallationConfig, installconfig.MaxConfigBytes)
	if err != nil {
		return Report{}, Installation{}, doctorError("configuration-read-failed")
	}
	configuration, err := installconfig.Decode(configBytes)
	clear(configBytes)
	if err != nil {
		return Report{}, Installation{}, doctorError("configuration-invalid")
	}
	metadataBytes, err := protectedstate.ReadExactFile(layout.InstallationMetadata, installmetadata.MaxBytes)
	if err != nil {
		return Report{}, Installation{}, doctorError("metadata-read-failed")
	}
	metadata, err := installmetadata.Decode(metadataBytes)
	clear(metadataBytes)
	if err != nil || metadata.InstallationRoot != installationRoot || metadata.GatewaySourceSHA != gatewaySourceSHA {
		return Report{}, Installation{}, doctorError("metadata-invalid")
	}
	if account.VerifyInstalled(configuration) != nil {
		return Report{}, Installation{}, doctorError("identity-policy-invalid")
	}
	if filesystem.VerifyInstalled(configuration) != nil {
		return Report{}, Installation{}, doctorError("filesystem-policy-invalid")
	}
	if runnerstore.VerifyInstalled(ctx, installationRoot, configuration) != nil {
		return Report{}, Installation{}, doctorError("runner-state-invalid")
	}
	if serviceinstall.VerifyFixedService(installationRoot) != nil ||
		runnerservice.VerifyFixedService(installationRoot, configuration.ControlIdentity.Name) != nil {
		return Report{}, Installation{}, doctorError("service-policy-invalid")
	}
	return Report{
		ProtectedState: true, Identities: true, FilesystemPolicy: true, RunnerState: true,
		ServicePolicy: true, ExecutionCredentialDenied: true, RunnerCredentialsDenied: true,
	}, Installation{Configuration: configuration, Metadata: metadata}, nil
}

func clear(content []byte) {
	for index := range content {
		content[index] = 0
	}
}

func doctorError(rule string) error { return &Error{Rule: rule} }
