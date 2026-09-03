//go:build windows

package uninstaller

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installmetadata"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/doctor"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

type fakeRemote struct{ operations *[]string }

func (remote fakeRemote) VerifyExclusivePrivate(context.Context) error {
	*remote.operations = append(*remote.operations, "remote-verify")
	return nil
}
func (remote fakeRemote) VerifyRunner(_ context.Context, name string) error {
	*remote.operations = append(*remote.operations, "runner-verify:"+name)
	return nil
}
func (remote fakeRemote) DeleteRunner(_ context.Context, name string) error {
	*remote.operations = append(*remote.operations, "runner-delete:"+name)
	return nil
}
func (remote fakeRemote) VerifyOwnedControlFile(_ context.Context, path, _ string) error {
	*remote.operations = append(*remote.operations, "file-verify:"+path)
	return nil
}
func (remote fakeRemote) DeleteOwnedControlFile(_ context.Context, path, _ string) error {
	*remote.operations = append(*remote.operations, "file-delete:"+path)
	return nil
}

func TestUninstallVerifiesOwnershipThenRemovesInSafeOrder(t *testing.T) {
	operations := []string{}
	configuration := installconfig.Config{
		ConfigVersion: installconfig.CurrentVersion, Platform: platformpath.Windows,
		ControlIdentity:   installconfig.Principal{Name: "awg-control", Identifier: "S-1-5-21-1-2-3-1001", PrimaryGroupIdentifier: "S-1-5-32-545"},
		ExecutionIdentity: installconfig.Principal{Name: "awg-exec", Identifier: "S-1-5-21-1-2-3-1002", PrimaryGroupIdentifier: "S-1-5-32-545"},
		ApprovedRoots:     []string{`C:\Users\Alice\Projects`}, ProfileRoot: `C:\AWG\Profile`, TempRoot: `C:\AWG\Temp`,
	}
	metadata := installmetadata.Metadata{
		MetadataVersion: installmetadata.Version, Platform: platformpath.Windows,
		InstallationRoot: `C:\ProgramData\AgentWorkstationGateway`, ControlRepository: "alice/example-control",
		RunnerName: "awg-windows-x64", GatewaySourceSHA: strings.Repeat("1", 40),
		ControlFiles: []installmetadata.ControlFile{
			{Path: ".github/workflows/execute-request.yml", SHA256: strings.Repeat("2", 64), Owned: true},
			{Path: "control-version.json", SHA256: strings.Repeat("3", 64), Owned: false},
		},
	}
	deps := dependencies{
		inspect: func(context.Context, string, string) (doctor.Report, doctor.Installation, error) {
			operations = append(operations, "local-verify")
			return doctor.Report{}, doctor.Installation{Configuration: configuration, Metadata: metadata}, nil
		},
		stopServices: func(context.Context) error { operations = append(operations, "services-stop"); return nil },
		deleteServices: func(context.Context, string, string) error {
			operations = append(operations, "services-delete")
			return nil
		},
		removeRunner: func(context.Context, string, installconfig.Config) error {
			operations = append(operations, "runner-local-remove")
			return nil
		},
		removeFilesystem: func(installconfig.Config) error { operations = append(operations, "filesystem-remove"); return nil },
		removeRoot:       func(string) error { operations = append(operations, "root-remove"); return nil },
		deleteAccounts:   func(installconfig.Config) error { operations = append(operations, "accounts-delete"); return nil },
	}
	err := run(context.Background(), metadata.InstallationRoot, metadata.GatewaySourceSHA, fakeRemote{operations: &operations}, deps)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"local-verify", "remote-verify", "runner-verify:awg-windows-x64", "file-verify:.github/workflows/execute-request.yml",
		"services-stop", "runner-delete:awg-windows-x64", "file-delete:.github/workflows/execute-request.yml",
		"services-delete", "runner-local-remove", "filesystem-remove", "root-remove", "accounts-delete",
	}
	if !reflect.DeepEqual(operations, expected) {
		t.Fatalf("unexpected uninstall order: %#v", operations)
	}
}
