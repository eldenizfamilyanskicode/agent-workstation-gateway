package installplan

import (
	"errors"
	"strings"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

const (
	placeholderControlSID   = "S-1-5-21-1000-1000-1000-1001"
	placeholderExecutionSID = "S-1-5-21-1000-1000-1000-1002"
	placeholderUsersSID     = "S-1-5-32-545"
)

func Validate(specification Spec) error {
	if specification.ConfigVersion != installconfig.CurrentVersion {
		return planError("config_version", "unsupported-version")
	}
	if specification.Platform != platformpath.Windows {
		return planError("platform", "unsupported-platform")
	}
	if err := platformpath.ValidateAbsolute(platformpath.Windows, specification.InstallationRoot); err != nil ||
		platformpath.IsFilesystemRoot(platformpath.Windows, specification.InstallationRoot) {
		return planError("installation_root", "invalid-or-filesystem-root")
	}
	configuration := configurationFromSpec(specification, IdentityBinding{
		ControlIdentifier: placeholderControlSID, ControlPrimaryGroupIdentifier: placeholderUsersSID,
		ExecutionIdentifier: placeholderExecutionSID, ExecutionPrimaryGroupIdentifier: placeholderUsersSID,
	})
	if err := installconfig.Validate(configuration); err != nil {
		return translateConfigError(err)
	}
	if strings.EqualFold(specification.ControlAccount, specification.ExecutionAccount) {
		return planError("execution_account", "must-differ-from-control")
	}
	protectedRoot := specification.InstallationRoot
	for _, root := range specification.ApprovedRoots {
		if platformpath.Overlaps(platformpath.Windows, protectedRoot, root) {
			return planError("installation_root", "overlaps-approved-root")
		}
	}
	if platformpath.Overlaps(platformpath.Windows, protectedRoot, specification.ProfileRoot) {
		return planError("installation_root", "overlaps-profile-root")
	}
	if platformpath.Overlaps(platformpath.Windows, protectedRoot, specification.TempRoot) {
		return planError("installation_root", "overlaps-temp-root")
	}
	return nil
}

func Build(specification Spec) (Plan, error) {
	if err := Validate(specification); err != nil {
		return Plan{}, err
	}
	layout, err := WindowsLayout(specification.InstallationRoot)
	if err != nil {
		return Plan{}, err
	}
	operations := []Operation{
		{Kind: "ensure_protected_directory", Target: layout.Root},
		{Kind: "ensure_protected_directory", Target: layout.BinDirectory},
		{Kind: "ensure_protected_directory", Target: layout.StateDirectory},
	}
	operations = append(operations, workloadFilesystemOperations(specification)...)
	operations = append(operations,
		Operation{Kind: "write_execution_credential", Target: layout.ExecutionCredential},
		Operation{Kind: "write_installed_configuration", Target: layout.InstallationConfig},
	)
	return Plan{
		PlanVersion: installconfig.CurrentVersion,
		Platform:    platformpath.Windows,
		Layout:      layout,
		Operations:  operations,
	}, nil
}

// WindowsLayout derives every protected installation path from one canonical
// administrator-selected root. Runtime code must use this same derivation and
// must not accept individual state paths from requests or environment data.
func WindowsLayout(installationRoot string) (Layout, error) {
	if platformpath.ValidateAbsolute(platformpath.Windows, installationRoot) != nil ||
		platformpath.IsFilesystemRoot(platformpath.Windows, installationRoot) {
		return Layout{}, planError("installation_root", "invalid-or-filesystem-root")
	}
	return Layout{
		Root:                installationRoot,
		BinDirectory:        joinWindows(installationRoot, "bin"),
		StateDirectory:      joinWindows(installationRoot, "state"),
		InstallationConfig:  joinWindows(installationRoot, "state", "installation.json"),
		ExecutionCredential: joinWindows(installationRoot, "state", "execution-credential.dpapi"),
	}, nil
}

func workloadFilesystemOperations(specification Spec) []Operation {
	operations := make([]Operation, 0, len(specification.ApprovedRoots)+2)
	for _, root := range specification.ApprovedRoots {
		operations = append(operations, Operation{Kind: "grant_execution_modify", Target: root})
	}
	operations = append(operations,
		Operation{Kind: "ensure_execution_profile", Target: specification.ProfileRoot},
		Operation{Kind: "ensure_execution_temp", Target: specification.TempRoot},
	)
	return operations
}

func Bind(specification Spec, binding IdentityBinding) (installconfig.Config, error) {
	if err := Validate(specification); err != nil {
		return installconfig.Config{}, err
	}
	configuration := configurationFromSpec(specification, binding)
	if err := installconfig.Validate(configuration); err != nil {
		return installconfig.Config{}, planError("identity_binding", "invalid")
	}
	return configuration, nil
}

func configurationFromSpec(specification Spec, binding IdentityBinding) installconfig.Config {
	return installconfig.Config{
		ConfigVersion: specification.ConfigVersion,
		Platform:      specification.Platform,
		ControlIdentity: installconfig.Principal{
			Name: specification.ControlAccount, Identifier: binding.ControlIdentifier,
			PrimaryGroupIdentifier: binding.ControlPrimaryGroupIdentifier,
		},
		ExecutionIdentity: installconfig.Principal{
			Name: specification.ExecutionAccount, Identifier: binding.ExecutionIdentifier,
			PrimaryGroupIdentifier: binding.ExecutionPrimaryGroupIdentifier,
		},
		ApprovedRoots: append([]string(nil), specification.ApprovedRoots...),
		Shells:        append([]installconfig.ShellBinding(nil), specification.Shells...),
		ProfileRoot:   specification.ProfileRoot,
		TempRoot:      specification.TempRoot,
		PathEntries:   append([]string(nil), specification.PathEntries...),
		Capabilities:  cloneCapabilities(specification.Capabilities),
	}
}

func cloneCapabilities(capabilities []installconfig.Capability) []installconfig.Capability {
	result := make([]installconfig.Capability, len(capabilities))
	copy(result, capabilities)
	return result
}

func translateConfigError(err error) error {
	var failure *installconfig.Error
	if !errors.As(err, &failure) {
		return planError("configuration", "invalid")
	}
	field := failure.Field
	field = strings.Replace(field, "control_identity.name", "control_account", 1)
	field = strings.Replace(field, "execution_identity.name", "execution_account", 1)
	return planError(field, failure.Rule)
}

func joinWindows(root string, segments ...string) string {
	return root + `\` + strings.Join(segments, `\`)
}
