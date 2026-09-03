//go:build windows

package runnerstore

import (
	"context"
	"errors"
	"os"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
)

func RemoveInstalled(ctx context.Context, installationRoot string, configuration installconfig.Config) error {
	if err := VerifyInstalled(ctx, installationRoot, configuration); err != nil {
		return storeError("installed-runner-conflict")
	}
	layout, err := installplan.WindowsLayout(installationRoot)
	if err != nil {
		return storeError("installation-layout-invalid")
	}
	if err := os.RemoveAll(layout.RunnerRoot); err != nil {
		return storeError("installed-runner-remove-failed")
	}
	if _, err := os.Lstat(layout.RunnerRoot); !errors.Is(err, os.ErrNotExist) {
		return storeError("installed-runner-remove-incomplete")
	}
	return nil
}
