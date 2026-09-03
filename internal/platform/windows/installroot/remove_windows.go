//go:build windows

package installroot

import (
	"os"
	"path/filepath"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installmetadata"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/protectedstate"
)

func RemoveInstalled(installationRoot string) error {
	layout, err := installplan.WindowsLayout(installationRoot)
	if err != nil {
		return rootError("installation-root-invalid")
	}
	for path, expected := range map[string][]string{
		layout.Root:           {"bin", "state"},
		layout.BinDirectory:   {"awg-broker.exe", "awg.exe"},
		layout.StateDirectory: {"execution-credential.dpapi", "installation.json", "management.json"},
	} {
		if protectedstate.ValidateExactDirectory(path) != nil || !hasExactEntries(path, expected) {
			return rootError("installed-directory-conflict")
		}
	}
	for path, maximum := range map[string]int{
		layout.ExecutionCredential:  protectedstate.MaxProtectedFileBytes,
		layout.InstallationConfig:   installconfig.MaxConfigBytes,
		layout.InstallationMetadata: installmetadata.MaxBytes,
	} {
		if protectedstate.ValidateExactFile(path, maximum) != nil {
			return rootError("installed-state-conflict")
		}
	}
	for _, path := range []string{layout.BrokerExecutable, layout.ControlExecutable} {
		if protectedstate.ValidateExactExecutable(path, protectedstate.MaxProtectedExecutableBytes) != nil {
			return rootError("installed-executable-conflict")
		}
	}
	for _, path := range []string{
		layout.InstallationMetadata, layout.InstallationConfig, layout.ExecutionCredential,
		layout.ControlExecutable, layout.BrokerExecutable,
	} {
		if err := os.Remove(path); err != nil {
			return rootError("installed-file-remove-failed")
		}
	}
	for _, path := range []string{layout.StateDirectory, layout.BinDirectory, layout.Root} {
		if err := os.Remove(path); err != nil {
			return rootError("installed-directory-remove-failed")
		}
	}
	return nil
}

func hasExactEntries(directory string, expected []string) bool {
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != len(expected) {
		return false
	}
	wanted := make(map[string]struct{}, len(expected))
	for _, name := range expected {
		wanted[name] = struct{}{}
	}
	for _, entry := range entries {
		if _, exists := wanted[entry.Name()]; !exists || entry.Type()&os.ModeSymlink != 0 ||
			filepath.Clean(entry.Name()) != entry.Name() {
			return false
		}
		delete(wanted, entry.Name())
	}
	return len(wanted) == 0
}
