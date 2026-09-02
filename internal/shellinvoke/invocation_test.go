package shellinvoke

import (
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionpolicy"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

func TestBuildUsesClosedArgumentsAndScriptStdin(t *testing.T) {
	marker := "SYNTHETIC-REQUEST-SCRIPT-9d61"
	tests := []struct {
		shell      v1.Shell
		executable string
		arguments  []string
	}{
		{v1.ShellBash, "/usr/bin/bash", []string{"--noprofile", "--norc", "-s"}},
		{v1.ShellGitBash, `C:\Program Files\Git\bin\bash.exe`, []string{"--noprofile", "--norc", "-s"}},
		{v1.ShellPowerShell, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-"}},
		{v1.ShellPwsh, `C:\Program Files\PowerShell\7\pwsh.exe`, []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-"}},
		{v1.ShellCmd, `C:\Windows\System32\cmd.exe`, []string{"/D", "/Q"}},
	}
	for _, test := range tests {
		t.Run(string(test.shell), func(t *testing.T) {
			invocation, err := Build(executionpolicy.LaunchPlan{
				Shell: test.shell, Executable: test.executable, Script: marker + "\n",
			})
			if err != nil {
				t.Fatal(err)
			}
			if invocation.Executable() != test.executable || !reflect.DeepEqual(invocation.Arguments(), test.arguments) {
				t.Fatalf("unexpected invocation: %q %#v", invocation.Executable(), invocation.Arguments())
			}
			for _, trusted := range append([]string{invocation.Executable()}, invocation.Arguments()...) {
				if strings.Contains(trusted, marker) {
					t.Fatal("request script reached trusted executable or argument data")
				}
			}
			script, err := io.ReadAll(invocation.ScriptReader())
			if err != nil || string(script) != marker+"\n" {
				t.Fatalf("script stdin changed: %q / %v", script, err)
			}
			arguments := invocation.Arguments()
			arguments[0] = marker
			if invocation.Arguments()[0] == marker {
				t.Fatal("caller can mutate the closed argument vector")
			}
		})
	}
}

func TestBuildCopiesScriptData(t *testing.T) {
	plan := executionpolicy.LaunchPlan{Shell: v1.ShellBash, Executable: "/usr/bin/bash", Script: "first\n"}
	invocation, err := Build(plan)
	if err != nil {
		t.Fatal(err)
	}
	plan.Script = "changed\n"
	script, err := io.ReadAll(invocation.ScriptReader())
	if err != nil || string(script) != "first\n" {
		t.Fatalf("invocation aliases launch plan script: %q / %v", script, err)
	}
}

func TestBuildRejectsOpenEndedOrIncompletePlans(t *testing.T) {
	tests := []executionpolicy.LaunchPlan{
		{Shell: "python", Executable: "/usr/bin/python", Script: "pass\n"},
		{Shell: v1.ShellBash, Script: "true\n"},
		{Shell: v1.ShellBash, Executable: "/usr/bin/bash"},
	}
	for _, plan := range tests {
		if _, err := Build(plan); err == nil {
			t.Fatalf("unsafe launch plan was accepted: %#v", plan)
		}
	}
}
