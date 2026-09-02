package installconfig

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

const (
	maxApprovedRoots = 16
	maxCapabilities  = 8
	maxPathEntries   = 32
	maxShells        = 5
)

var principalNamePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
var windowsSIDPattern = regexp.MustCompile(`^S-1-[0-9]+(?:-[0-9]+){1,14}$`)
var linuxUIDPattern = regexp.MustCompile(`^uid:[1-9][0-9]{0,9}$`)

var supportedCapabilities = map[Capability]struct{}{
	CapabilityDocker: {},
}

var platformShells = map[platformpath.Platform]map[v1.Shell]struct{}{
	platformpath.Windows: {
		v1.ShellCmd: {}, v1.ShellGitBash: {}, v1.ShellPowerShell: {}, v1.ShellPwsh: {},
	},
	platformpath.Linux: {
		v1.ShellBash: {}, v1.ShellPwsh: {},
	},
}

func Validate(configuration Config) error {
	if configuration.ConfigVersion != CurrentVersion {
		return configError("config_version", "unsupported-version")
	}
	if _, supported := platformShells[configuration.Platform]; !supported {
		return configError("platform", "unsupported-platform")
	}
	if err := validatePrincipal("control_identity", configuration.Platform, configuration.ControlIdentity); err != nil {
		return err
	}
	if err := validatePrincipal("execution_identity", configuration.Platform, configuration.ExecutionIdentity); err != nil {
		return err
	}
	if principalsEqual(configuration.Platform, configuration.ControlIdentity, configuration.ExecutionIdentity) {
		return configError("execution_identity", "must-differ-from-control")
	}
	if err := validateRoots(configuration); err != nil {
		return err
	}
	if err := validateShells(configuration); err != nil {
		return err
	}
	if err := validatePathEntries(configuration); err != nil {
		return err
	}
	return validateCapabilities(configuration.Capabilities)
}

func validatePrincipal(field string, platform platformpath.Platform, principal Principal) error {
	if !principalNamePattern.MatchString(principal.Name) {
		return configError(field+".name", "invalid-name")
	}
	switch platform {
	case platformpath.Windows:
		if !windowsSIDPattern.MatchString(principal.Identifier) {
			return configError(field+".identifier", "invalid-windows-sid")
		}
	case platformpath.Linux:
		if !linuxUIDPattern.MatchString(principal.Identifier) {
			return configError(field+".identifier", "invalid-linux-uid")
		}
		uid, err := strconv.ParseUint(strings.TrimPrefix(principal.Identifier, "uid:"), 10, 32)
		if err != nil || uid == 0 || uid == 4294967295 {
			return configError(field+".identifier", "invalid-linux-uid")
		}
	}
	return nil
}

func principalsEqual(platform platformpath.Platform, left Principal, right Principal) bool {
	if platform == platformpath.Windows {
		return strings.EqualFold(left.Identifier, right.Identifier)
	}
	return left.Identifier == right.Identifier
}

func validateRoots(configuration Config) error {
	if configuration.ApprovedRoots == nil || len(configuration.ApprovedRoots) == 0 || len(configuration.ApprovedRoots) > maxApprovedRoots {
		return configError("approved_roots", "outside-count-limit")
	}
	if err := validateNonRootPath("profile_root", configuration.Platform, configuration.ProfileRoot); err != nil {
		return err
	}
	if err := validateNonRootPath("temp_root", configuration.Platform, configuration.TempRoot); err != nil {
		return err
	}
	if platformpath.Equal(configuration.Platform, configuration.ProfileRoot, configuration.TempRoot) {
		return configError("temp_root", "must-differ-from-profile")
	}
	for rootIndex, root := range configuration.ApprovedRoots {
		if err := validateNonRootPath("approved_roots", configuration.Platform, root); err != nil {
			return err
		}
		if platformpath.Overlaps(configuration.Platform, root, configuration.ProfileRoot) || platformpath.Overlaps(configuration.Platform, root, configuration.TempRoot) {
			return configError("approved_roots", "overlaps-execution-state")
		}
		for otherIndex := 0; otherIndex < rootIndex; otherIndex++ {
			if platformpath.Overlaps(configuration.Platform, root, configuration.ApprovedRoots[otherIndex]) {
				return configError("approved_roots", "duplicate-or-overlapping-root")
			}
		}
	}
	return nil
}

func validateShells(configuration Config) error {
	if configuration.Shells == nil || len(configuration.Shells) == 0 || len(configuration.Shells) > maxShells {
		return configError("shells", "outside-count-limit")
	}
	seenShells := make(map[v1.Shell]struct{}, len(configuration.Shells))
	seenExecutables := make([]string, 0, len(configuration.Shells))
	for _, binding := range configuration.Shells {
		if _, supported := platformShells[configuration.Platform][binding.Shell]; !supported {
			return configError("shells.shell", "unsupported-for-platform")
		}
		if _, duplicate := seenShells[binding.Shell]; duplicate {
			return configError("shells.shell", "duplicate-shell")
		}
		seenShells[binding.Shell] = struct{}{}
		if err := validateProtectedToolPath(configuration, "shells.executable", binding.Executable); err != nil {
			return err
		}
		for _, executable := range seenExecutables {
			if platformpath.Equal(configuration.Platform, executable, binding.Executable) {
				return configError("shells.executable", "duplicate-executable")
			}
		}
		seenExecutables = append(seenExecutables, binding.Executable)
	}
	return nil
}

func validatePathEntries(configuration Config) error {
	if configuration.PathEntries == nil || len(configuration.PathEntries) == 0 || len(configuration.PathEntries) > maxPathEntries {
		return configError("path_entries", "outside-count-limit")
	}
	for entryIndex, entry := range configuration.PathEntries {
		if err := validateProtectedToolPath(configuration, "path_entries", entry); err != nil {
			return err
		}
		for otherIndex := 0; otherIndex < entryIndex; otherIndex++ {
			if platformpath.Equal(configuration.Platform, entry, configuration.PathEntries[otherIndex]) {
				return configError("path_entries", "duplicate-path")
			}
		}
	}
	return nil
}

func validateProtectedToolPath(configuration Config, field string, value string) error {
	if err := validateNonRootPath(field, configuration.Platform, value); err != nil {
		return err
	}
	for _, root := range configuration.ApprovedRoots {
		if platformpath.Contains(configuration.Platform, root, value) {
			return configError(field, "inside-approved-root")
		}
	}
	return nil
}

func validateNonRootPath(field string, platform platformpath.Platform, value string) error {
	if err := platformpath.ValidateAbsolute(platform, value); err != nil {
		return configError(field, "invalid-absolute-path")
	}
	if platformpath.IsFilesystemRoot(platform, value) {
		return configError(field, "filesystem-root-forbidden")
	}
	return nil
}

func validateCapabilities(capabilities []Capability) error {
	if capabilities == nil || len(capabilities) > maxCapabilities {
		return configError("capabilities", "required-bounded-array")
	}
	seen := make(map[Capability]struct{}, len(capabilities))
	for _, capability := range capabilities {
		if _, supported := supportedCapabilities[capability]; !supported {
			return configError("capabilities", "unsupported-capability")
		}
		if _, duplicate := seen[capability]; duplicate {
			return configError("capabilities", "duplicate-capability")
		}
		seen[capability] = struct{}{}
	}
	return nil
}
