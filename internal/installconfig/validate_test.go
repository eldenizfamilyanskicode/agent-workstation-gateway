package installconfig

import (
	"testing"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

func TestValidateAcceptsSafeWindowsAndLinuxDefaults(t *testing.T) {
	for _, configuration := range []Config{validWindowsConfig(), validLinuxConfig()} {
		if err := Validate(configuration); err != nil {
			t.Fatalf("valid %s configuration rejected: %v", configuration.Platform, err)
		}
		if len(configuration.Capabilities) != 0 {
			t.Fatal("base configuration unexpectedly enables a powerful capability")
		}
	}
}

func TestValidateRejectsIdentityRootAndStateBoundaryViolations(t *testing.T) {
	tests := []struct {
		name  string
		alter func(*Config)
		field string
		rule  string
	}{
		{name: "version", alter: func(config *Config) { config.ConfigVersion = 2 }, field: "config_version", rule: "unsupported-version"},
		{name: "platform", alter: func(config *Config) { config.Platform = "other" }, field: "platform", rule: "unsupported-platform"},
		{name: "principal name", alter: func(config *Config) { config.ControlIdentity.Name = "Administrator" }, field: "control_identity.name", rule: "invalid-name"},
		{name: "principal sid", alter: func(config *Config) { config.ExecutionIdentity.Identifier = "awg-exec" }, field: "execution_identity.identifier", rule: "invalid-windows-sid"},
		{name: "primary group sid", alter: func(config *Config) { config.ExecutionIdentity.PrimaryGroupIdentifier = "users" }, field: "execution_identity.primary_group_identifier", rule: "invalid-windows-sid"},
		{name: "same identity", alter: func(config *Config) { config.ExecutionIdentity.Identifier = config.ControlIdentity.Identifier }, field: "execution_identity", rule: "must-differ-from-control"},
		{name: "no roots", alter: func(config *Config) { config.ApprovedRoots = []string{} }, field: "approved_roots", rule: "outside-count-limit"},
		{name: "drive root", alter: func(config *Config) { config.ApprovedRoots = []string{`C:\`} }, field: "approved_roots", rule: "filesystem-root-forbidden"},
		{name: "overlapping roots", alter: func(config *Config) {
			config.ApprovedRoots = []string{`C:\Users\Alice\Projects`, `C:\Users\Alice\Projects\demo`}
		}, field: "approved_roots", rule: "duplicate-or-overlapping-root"},
		{name: "profile exposed", alter: func(config *Config) { config.ApprovedRoots = []string{`C:\ProgramData\AWG`} }, field: "approved_roots", rule: "overlaps-execution-state"},
		{name: "same temp", alter: func(config *Config) { config.TempRoot = config.ProfileRoot }, field: "temp_root", rule: "must-differ-from-profile"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration := validWindowsConfig()
			test.alter(&configuration)
			assertConfigError(t, Validate(configuration), test.field, test.rule)
		})
	}
}

func TestValidateRejectsMutableOrAmbiguousToolConfiguration(t *testing.T) {
	tests := []struct {
		name  string
		alter func(*Config)
		field string
		rule  string
	}{
		{name: "no shells", alter: func(config *Config) { config.Shells = nil }, field: "shells", rule: "outside-count-limit"},
		{name: "incompatible shell", alter: func(config *Config) { config.Shells[0].Shell = v1.ShellBash }, field: "shells.shell", rule: "unsupported-for-platform"},
		{name: "duplicate shell", alter: func(config *Config) { config.Shells = append(config.Shells, config.Shells[0]) }, field: "shells.shell", rule: "duplicate-shell"},
		{name: "relative executable", alter: func(config *Config) { config.Shells[0].Executable = `pwsh.exe` }, field: "shells.executable", rule: "invalid-absolute-path"},
		{name: "mutable executable", alter: func(config *Config) { config.Shells[0].Executable = `C:\Users\Alice\Projects\pwsh.exe` }, field: "shells.executable", rule: "inside-approved-root"},
		{name: "no path", alter: func(config *Config) { config.PathEntries = nil }, field: "path_entries", rule: "outside-count-limit"},
		{name: "duplicate path", alter: func(config *Config) { config.PathEntries = append(config.PathEntries, config.PathEntries[0]) }, field: "path_entries", rule: "duplicate-path"},
		{name: "nil capabilities", alter: func(config *Config) { config.Capabilities = nil }, field: "capabilities", rule: "required-bounded-array"},
		{name: "unknown capability", alter: func(config *Config) { config.Capabilities = []Capability{"administrator"} }, field: "capabilities", rule: "unsupported-capability"},
		{name: "duplicate capability", alter: func(config *Config) { config.Capabilities = []Capability{CapabilityDocker, CapabilityDocker} }, field: "capabilities", rule: "duplicate-capability"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration := validWindowsConfig()
			test.alter(&configuration)
			assertConfigError(t, Validate(configuration), test.field, test.rule)
		})
	}
}

func TestValidateAcceptsExplicitDockerCapability(t *testing.T) {
	configuration := validLinuxConfig()
	configuration.Capabilities = []Capability{CapabilityDocker}
	if err := Validate(configuration); err != nil {
		t.Fatalf("explicit closed capability rejected: %v", err)
	}
}

func TestValidateRejectsInvalidLinuxUID(t *testing.T) {
	configuration := validLinuxConfig()
	configuration.ExecutionIdentity.Identifier = "uid:4294967295"
	assertConfigError(t, Validate(configuration), "execution_identity.identifier", "invalid-linux-uid")
	configuration = validLinuxConfig()
	configuration.ExecutionIdentity.PrimaryGroupIdentifier = "gid:4294967295"
	assertConfigError(t, Validate(configuration), "execution_identity.primary_group_identifier", "invalid-linux-gid")
}

func validWindowsConfig() Config {
	return Config{
		ConfigVersion: CurrentVersion,
		Platform:      platformpath.Windows,
		ControlIdentity: Principal{
			Name: "awg-control", Identifier: "S-1-5-21-1000-1000-1000-1001", PrimaryGroupIdentifier: "S-1-5-32-545",
		},
		ExecutionIdentity: Principal{
			Name: "awg-exec", Identifier: "S-1-5-21-1000-1000-1000-1002", PrimaryGroupIdentifier: "S-1-5-32-545",
		},
		ApprovedRoots: []string{`C:\Users\Alice\Projects`},
		Shells: []ShellBinding{
			{Shell: v1.ShellPwsh, Executable: `C:\Program Files\PowerShell\7\pwsh.exe`},
		},
		ProfileRoot:  `C:\ProgramData\AWG\Profiles\Exec`,
		TempRoot:     `C:\ProgramData\AWG\Temp`,
		PathEntries:  []string{`C:\Program Files\PowerShell\7`, `C:\Windows\System32`},
		Capabilities: []Capability{},
	}
}

func validLinuxConfig() Config {
	return Config{
		ConfigVersion: CurrentVersion,
		Platform:      platformpath.Linux,
		ControlIdentity: Principal{
			Name: "awg-control", Identifier: "uid:1001", PrimaryGroupIdentifier: "gid:1001",
		},
		ExecutionIdentity: Principal{
			Name: "awg-exec", Identifier: "uid:1002", PrimaryGroupIdentifier: "gid:1002",
		},
		ApprovedRoots: []string{"/srv/awg/projects"},
		Shells: []ShellBinding{
			{Shell: v1.ShellBash, Executable: "/bin/bash"},
		},
		ProfileRoot:  "/var/lib/awg/exec",
		TempRoot:     "/var/tmp/awg-exec",
		PathEntries:  []string{"/usr/bin", "/bin"},
		Capabilities: []Capability{},
	}
}
