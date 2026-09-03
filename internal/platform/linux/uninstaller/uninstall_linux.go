//go:build linux

package uninstaller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/linux/doctor"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/linux/installer"
)

type Remote interface {
	VerifyExclusivePrivate(context.Context) error
	VerifyRunner(context.Context, string) error
	DeleteRunner(context.Context, string) error
	VerifyOwnedControlFile(context.Context, string, string) error
	DeleteOwnedControlFile(context.Context, string, string) error
}

type Error struct{ Rule string }

func (failure *Error) Error() string { return fmt.Sprintf("Linux uninstall failed: %s", failure.Rule) }

func Run(ctx context.Context, installationRoot, sourceSHA string, remote Remote) error {
	if ctx == nil || remote == nil || os.Geteuid() != 0 {
		return uninstallError("root-uninstaller-required")
	}
	_, installation, err := doctor.InspectInstalled(ctx, installationRoot, sourceSHA)
	if err != nil {
		return uninstallError("installed-state-invalid")
	}
	metadata := installation.Metadata
	configuration := installation.Configuration
	if remote.VerifyExclusivePrivate(ctx) != nil {
		return uninstallError("private-repository-invalid")
	}
	if remote.VerifyRunner(ctx, metadata.RunnerName) != nil {
		return uninstallError("remote-runner-invalid")
	}
	for _, file := range metadata.ControlFiles {
		if file.Owned && remote.VerifyOwnedControlFile(ctx, file.Path, file.SHA256) != nil {
			return uninstallError("remote-control-file-invalid")
		}
	}
	if run(ctx, "systemctl", "disable", "--now", installer.RunnerUnitName, installer.BrokerUnitName) != nil {
		return uninstallError("service-stop-failed")
	}
	if remote.DeleteRunner(ctx, metadata.RunnerName) != nil {
		return uninstallError("remote-runner-delete-failed")
	}
	for _, file := range metadata.ControlFiles {
		if file.Owned && remote.DeleteOwnedControlFile(ctx, file.Path, file.SHA256) != nil {
			return uninstallError("remote-control-file-delete-failed")
		}
	}
	for _, path := range []string{installer.RunnerUnitPath, installer.BrokerUnitPath} {
		if err := os.Remove(path); err != nil {
			return uninstallError("service-unit-remove-failed")
		}
	}
	if run(ctx, "systemctl", "daemon-reload") != nil {
		return uninstallError("service-reload-failed")
	}
	if restoreACL(ctx, installationRoot) != nil {
		return uninstallError("filesystem-policy-remove-failed")
	}
	layout, _ := installLayout(installationRoot)
	for _, path := range []string{layout.RunnerRoot, configuration.TempRoot, configuration.ProfileRoot, layout.Root} {
		if err := removeExactTree(path); err != nil {
			return uninstallError("owned-state-remove-failed")
		}
	}
	for _, name := range []string{configuration.ExecutionIdentity.Name, configuration.ControlIdentity.Name} {
		if run(ctx, "userdel", name) != nil || run(ctx, "groupdel", name) != nil {
			return uninstallError("identity-remove-failed")
		}
	}
	return nil
}

func restoreACL(ctx context.Context, installationRoot string) error {
	layout, err := installLayout(installationRoot)
	if err != nil {
		return err
	}
	backup, err := os.Open(layout.ACLBackup)
	if err != nil {
		return err
	}
	defer backup.Close()
	command := exec.CommandContext(ctx, "setfacl", "--restore=-")
	command.Stdin = backup
	command.Stdout, command.Stderr = io.Discard, io.Discard
	return command.Run()
}

type layoutPaths struct {
	Root, RunnerRoot, ACLBackup string
}

func installLayout(root string) (layoutPaths, error) {
	layout, err := installplan.LinuxLayout(root)
	if err != nil {
		return layoutPaths{}, err
	}
	return layoutPaths{Root: layout.Root, RunnerRoot: layout.RunnerRoot, ACLBackup: layout.StateDirectory + "/" + installer.ACLBackupName}, nil
}

func removeExactTree(path string) error {
	if path == "" || path == "/" {
		return uninstallError("unsafe-remove-target")
	}
	if err := os.RemoveAll(path); err != nil {
		return err
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return uninstallError("remove-incomplete")
	}
	return nil
}

func run(ctx context.Context, executable string, args ...string) error {
	command := exec.CommandContext(ctx, executable, args...)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	return command.Run()
}

func uninstallError(rule string) error { return &Error{Rule: rule} }
