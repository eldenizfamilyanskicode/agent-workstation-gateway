//go:build windows

package uninstaller

import (
	"context"
	"fmt"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/account"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/doctor"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/filesystem"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/installroot"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/runnerstore"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/servicectl"
)

type Remote interface {
	VerifyExclusivePrivate(context.Context) error
	VerifyRunner(context.Context, string) error
	DeleteRunner(context.Context, string) error
	VerifyOwnedControlFile(context.Context, string, string) error
	DeleteOwnedControlFile(context.Context, string, string) error
}

type dependencies struct {
	inspect          func(context.Context, string, string) (doctor.Report, doctor.Installation, error)
	stopServices     func(context.Context) error
	deleteServices   func(context.Context, string, string) error
	removeRunner     func(context.Context, string, installconfig.Config) error
	removeFilesystem func(installconfig.Config) error
	removeRoot       func(string) error
	deleteAccounts   func(installconfig.Config) error
}

type Error struct{ Rule string }

func (failure *Error) Error() string {
	return fmt.Sprintf("Windows uninstall failed: %s", failure.Rule)
}

func Run(ctx context.Context, installationRoot string, gatewaySourceSHA string, remote Remote) error {
	return run(ctx, installationRoot, gatewaySourceSHA, remote, dependencies{
		inspect:          doctor.InspectInstalled,
		stopServices:     servicectl.Stop,
		deleteServices:   servicectl.Delete,
		removeRunner:     runnerstore.RemoveInstalled,
		removeFilesystem: filesystem.RemoveInstalled,
		removeRoot:       installroot.RemoveInstalled,
		deleteAccounts:   account.DeleteInstalled,
	})
}

func run(ctx context.Context, installationRoot string, gatewaySourceSHA string, remote Remote, deps dependencies) error {
	if ctx == nil || remote == nil || deps.inspect == nil || deps.stopServices == nil || deps.deleteServices == nil ||
		deps.removeRunner == nil || deps.removeFilesystem == nil || deps.removeRoot == nil || deps.deleteAccounts == nil {
		return uninstallError("dependency-required")
	}
	_, installation, err := deps.inspect(ctx, installationRoot, gatewaySourceSHA)
	if err != nil {
		return uninstallError("installed-state-invalid")
	}
	metadata := installation.Metadata
	configuration := installation.Configuration
	if err := remote.VerifyExclusivePrivate(ctx); err != nil {
		return uninstallError("private-repository-invalid")
	}
	if err := remote.VerifyRunner(ctx, metadata.RunnerName); err != nil {
		return uninstallError("remote-runner-invalid")
	}
	for _, file := range metadata.ControlFiles {
		if file.Owned {
			if err := remote.VerifyOwnedControlFile(ctx, file.Path, file.SHA256); err != nil {
				return uninstallError("remote-control-file-invalid")
			}
		}
	}
	if err := deps.stopServices(ctx); err != nil {
		return uninstallError("service-stop-failed")
	}
	if err := remote.DeleteRunner(ctx, metadata.RunnerName); err != nil {
		return uninstallError("remote-runner-delete-failed")
	}
	for _, file := range metadata.ControlFiles {
		if file.Owned {
			if err := remote.DeleteOwnedControlFile(ctx, file.Path, file.SHA256); err != nil {
				return uninstallError("remote-control-file-delete-failed")
			}
		}
	}
	if err := deps.deleteServices(ctx, installationRoot, configuration.ControlIdentity.Name); err != nil {
		return uninstallError("service-delete-failed")
	}
	if err := deps.removeRunner(ctx, installationRoot, configuration); err != nil {
		return uninstallError("runner-state-remove-failed")
	}
	if err := deps.removeFilesystem(configuration); err != nil {
		return uninstallError("filesystem-policy-remove-failed")
	}
	if err := deps.removeRoot(installationRoot); err != nil {
		return uninstallError("installation-root-remove-failed")
	}
	if err := deps.deleteAccounts(configuration); err != nil {
		return uninstallError("account-delete-failed")
	}
	return nil
}

func uninstallError(rule string) error { return &Error{Rule: rule} }
