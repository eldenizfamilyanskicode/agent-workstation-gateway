package workloadenv

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

func TestBuildWindowsEnvironmentProjectsOnlyValidatedSafeValues(t *testing.T) {
	configuration := windowsConfig()
	base := []string{
		`SystemRoot=C:\Windows`, `WINDIR=C:\Windows`, `PATHEXT=.COM;.EXE;.BAT;.CMD`, `OS=Windows_NT`,
		`PROCESSOR_ARCHITECTURE=AMD64`, `GITHUB_TOKEN=SYNTHETIC-GITHUB-MARKER`,
		`RUNNER_TRACKING_ID=SYNTHETIC-RUNNER-MARKER`, `GH_TOKEN=SYNTHETIC-GH-MARKER`,
		`AWS_SECRET_ACCESS_KEY=SYNTHETIC-CLOUD-MARKER`, `HUMAN_SECRET=SYNTHETIC-HUMAN-MARKER`,
		`=C:=C:\runner\work`,
	}
	result, err := Build(configuration, base, validContext())
	if err != nil {
		t.Fatal(err)
	}
	values := environmentMap(t, result)
	assertEnvironmentValue(t, values, "USERPROFILE", configuration.ProfileRoot)
	assertEnvironmentValue(t, values, "TEMP", configuration.TempRoot)
	assertEnvironmentValue(t, values, "PATH", strings.Join(configuration.PathEntries, ";"))
	assertEnvironmentValue(t, values, "SystemRoot", `C:\Windows`)
	assertAbsentNames(t, values, "GITHUB_TOKEN", "RUNNER_TRACKING_ID", "GH_TOKEN", "AWS_SECRET_ACCESS_KEY", "HUMAN_SECRET")
	if !sortStableForPlatform(platformpath.Windows, result) {
		t.Fatal("Windows environment is not deterministically sorted")
	}
}

func TestBuildLinuxEnvironmentProjectsOnlyValidatedSafeValues(t *testing.T) {
	configuration := linuxConfig()
	base := []string{"LANG=C.UTF-8", "TZ=UTC", "GITHUB_TOKEN=SYNTHETIC-GITHUB-MARKER", "SSH_AUTH_SOCK=/tmp/agent.sock"}
	result, err := Build(configuration, base, validContext())
	if err != nil {
		t.Fatal(err)
	}
	values := environmentMap(t, result)
	assertEnvironmentValue(t, values, "HOME", configuration.ProfileRoot)
	assertEnvironmentValue(t, values, "TMPDIR", configuration.TempRoot)
	assertEnvironmentValue(t, values, "PATH", strings.Join(configuration.PathEntries, ":"))
	assertEnvironmentValue(t, values, "LANG", "C.UTF-8")
	assertAbsentNames(t, values, "GITHUB_TOKEN", "SSH_AUTH_SOCK")
	if !sortStableForPlatform(platformpath.Linux, result) {
		t.Fatal("Linux environment is not deterministically sorted")
	}
}

func TestBuildEnvironmentRejectsInvalidSafeInputsAndContext(t *testing.T) {
	tests := []struct {
		name    string
		config  installconfig.Config
		base    []string
		context Context
		field   string
		rule    string
	}{
		{name: "duplicate Windows key", config: windowsConfig(), base: []string{`SystemRoot=C:\Windows`, `SYSTEMROOT=C:\Windows`, `WINDIR=C:\Windows`}, context: validContext(), field: "safe_base", rule: "duplicate-allowed-key"},
		{name: "relative system root", config: windowsConfig(), base: []string{`SystemRoot=Windows`, `WINDIR=C:\Windows`}, context: validContext(), field: "safe_base", rule: "invalid-system-path"},
		{name: "missing system path", config: windowsConfig(), base: []string{`SystemRoot=C:\Windows`}, context: validContext(), field: "safe_base", rule: "missing-windows-system-paths"},
		{name: "inconsistent system paths", config: windowsConfig(), base: []string{`SystemRoot=C:\Windows`, `WINDIR=D:\Windows`}, context: validContext(), field: "safe_base", rule: "inconsistent-windows-system-paths"},
		{name: "invalid locale", config: linuxConfig(), base: []string{"LANG=SYNTHETIC SECRET"}, context: validContext(), field: "safe_base", rule: "invalid-locale"},
		{name: "malformed", config: linuxConfig(), base: []string{"LANG"}, context: validContext(), field: "safe_base", rule: "invalid-entry"},
		{name: "request id", config: linuxConfig(), base: nil, context: Context{RequestID: "../request", SessionID: "session", AttemptID: "attempt"}, field: "request_id", rule: "invalid-identifier"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Build(test.config, test.base, test.context)
			assertEnvironmentError(t, err, test.field, test.rule)
		})
	}
}

func TestBuildEnvironmentIsIndependentOfInputOrder(t *testing.T) {
	configuration := linuxConfig()
	left, err := Build(configuration, []string{"TZ=UTC", "LANG=C"}, validContext())
	if err != nil {
		t.Fatal(err)
	}
	right, err := Build(configuration, []string{"LANG=C", "TZ=UTC"}, validContext())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(left, right) {
		t.Fatalf("safe input order changed environment: %#v / %#v", left, right)
	}
}

func environmentMap(t *testing.T, environment []string) map[string]string {
	t.Helper()
	result := make(map[string]string, len(environment))
	for _, entry := range environment {
		separator := strings.IndexByte(entry, '=')
		if separator <= 0 {
			t.Fatalf("invalid environment entry shape")
		}
		result[entry[:separator]] = entry[separator+1:]
	}
	return result
}

func assertEnvironmentValue(t *testing.T, values map[string]string, name string, expected string) {
	t.Helper()
	if values[name] != expected {
		t.Fatalf("unexpected value for %s", name)
	}
}

func assertAbsentNames(t *testing.T, values map[string]string, names ...string) {
	t.Helper()
	for _, name := range names {
		if _, exists := values[name]; exists {
			t.Fatalf("forbidden environment name was retained: %s", name)
		}
	}
}

func sortStableForPlatform(platform platformpath.Platform, environment []string) bool {
	previous := ""
	for index, entry := range environment {
		name := strings.SplitN(entry, "=", 2)[0]
		if platform == platformpath.Windows {
			name = strings.ToLower(name)
		}
		if index > 0 && name < previous {
			return false
		}
		previous = name
	}
	return true
}

func assertEnvironmentError(t *testing.T, err error, field string, rule string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected environment error %s/%s", field, rule)
	}
	var validationFailure *Error
	if !errors.As(err, &validationFailure) {
		t.Fatalf("expected environment error, got %T: %v", err, err)
	}
	if validationFailure.Field != field || validationFailure.Rule != rule {
		t.Fatalf("expected %s/%s, got %s/%s", field, rule, validationFailure.Field, validationFailure.Rule)
	}
}

func validContext() Context {
	return Context{RequestID: "req-000001", SessionID: "example-session", AttemptID: "attempt-000001"}
}

func windowsConfig() installconfig.Config {
	return installconfig.Config{
		ConfigVersion: installconfig.CurrentVersion,
		Platform:      platformpath.Windows,
		ControlIdentity: installconfig.Principal{
			Name: "awg-control", Identifier: "S-1-5-21-1000-1000-1000-1001",
		},
		ExecutionIdentity: installconfig.Principal{
			Name: "awg-exec", Identifier: "S-1-5-21-1000-1000-1000-1002",
		},
		ApprovedRoots: []string{`C:\Users\Alice\Projects`},
		Shells: []installconfig.ShellBinding{
			{Shell: v1.ShellPwsh, Executable: `C:\Program Files\PowerShell\7\pwsh.exe`},
		},
		ProfileRoot: `C:\ProgramData\AWG\Profiles\Exec`, TempRoot: `C:\ProgramData\AWG\Temp`,
		PathEntries: []string{`C:\Program Files\PowerShell\7`, `C:\Windows\System32`}, Capabilities: []installconfig.Capability{},
	}
}

func linuxConfig() installconfig.Config {
	return installconfig.Config{
		ConfigVersion: installconfig.CurrentVersion,
		Platform:      platformpath.Linux,
		ControlIdentity: installconfig.Principal{
			Name: "awg-control", Identifier: "uid:1001",
		},
		ExecutionIdentity: installconfig.Principal{
			Name: "awg-exec", Identifier: "uid:1002",
		},
		ApprovedRoots: []string{"/srv/awg/projects"},
		Shells: []installconfig.ShellBinding{
			{Shell: v1.ShellBash, Executable: "/bin/bash"},
		},
		ProfileRoot: "/var/lib/awg/exec", TempRoot: "/var/tmp/awg-exec",
		PathEntries: []string{"/usr/bin", "/bin"}, Capabilities: []installconfig.Capability{},
	}
}
