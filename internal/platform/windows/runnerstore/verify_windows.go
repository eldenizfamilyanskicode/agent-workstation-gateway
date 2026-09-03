//go:build windows

package runnerstore

import (
	"context"
	"path/filepath"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

func VerifyInstalled(ctx context.Context, installationRoot string, configuration installconfig.Config) error {
	if ctx == nil || configuration.Platform != platformpath.Windows || installconfig.Validate(configuration) != nil {
		return storeError("installed-configuration-invalid")
	}
	layout, err := installplan.WindowsLayout(installationRoot)
	if err != nil {
		return storeError("installation-layout-invalid")
	}
	control, err := accountSID(configuration.ControlIdentity.Identifier)
	if err != nil {
		return storeError("control-sid-invalid")
	}
	execution, err := accountSID(configuration.ExecutionIdentity.Identifier)
	if err != nil || execution.Equals(control) {
		return storeError("execution-sid-invalid")
	}
	for _, path := range []string{layout.RunnerRoot, layout.RunnerWorkDirectory, layout.RunnerResponseDirectory} {
		if err := contextError(ctx); err != nil {
			return err
		}
		if err := validateObject(path, true, control, execution); err != nil {
			return storeError("runner-directory-policy-invalid")
		}
	}
	for _, relative := range []string{
		".runner", ".credentials", ".credentials_rsaparams", filepath.Join("bin", "Runner.Listener.exe"), filepath.Join("bin", "RunnerService.exe"),
	} {
		if err := contextError(ctx); err != nil {
			return err
		}
		if err := validateObject(filepath.Join(layout.RunnerRoot, relative), false, control, execution); err != nil {
			return storeError("runner-file-policy-invalid")
		}
	}
	return nil
}
