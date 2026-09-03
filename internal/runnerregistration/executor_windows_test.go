//go:build windows

package runnerregistration

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

const nativeToken = "synthetic-native-token-1"

func TestWindowsExecutorRunsDirectlyWithIsolatedSecretEnvironment(t *testing.T) {
	invocation := nativeInvocation(t, "native-success")
	t.Setenv("UNRELATED_AWG_SECRET", "must-not-be-inherited")
	result, err := NewWindowsExecutor().Run(context.Background(), invocation, []byte(nativeToken))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Started || result.ExitCode != 0 {
		t.Fatalf("unexpected native process result: %#v", result)
	}
}

func TestWindowsExecutorTerminatesOutputAndDeadlineViolations(t *testing.T) {
	for _, test := range []struct {
		name       string
		runnerName string
		context    func() (context.Context, context.CancelFunc)
		rule       string
	}{
		{
			name: "output", runnerName: "output-limit",
			context: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 10*time.Second)
			},
			rule: "executor-output-limit",
		},
		{
			name: "deadline", runnerName: "deadline",
			context: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 100*time.Millisecond)
			},
			rule: "executor-context-cancelled",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := test.context()
			defer cancel()
			result, err := NewWindowsExecutor().Run(ctx, nativeInvocation(t, test.runnerName), []byte(nativeToken))
			if !result.Started {
				t.Fatal("native violation process never started")
			}
			assertRule(t, err, test.rule)
		})
	}
}

func TestWindowsExecutorRejectsInvocationDriftBeforeProcessCreation(t *testing.T) {
	valid := nativeInvocation(t, "native-policy")
	for _, test := range []struct {
		name   string
		mutate func(*Invocation)
	}{
		{name: "token key", mutate: func(value *Invocation) { value.TokenEnvironment = "TOKEN" }},
		{name: "executable", mutate: func(value *Invocation) { value.Executable = `C:\Windows\System32\cmd.exe` }},
		{name: "extra argument", mutate: func(value *Invocation) { value.Arguments = append(value.Arguments, "--replace") }},
		{name: "repository", mutate: func(value *Invocation) { value.Arguments[3] = "https://example.invalid/control" }},
		{name: "work", mutate: func(value *Invocation) { value.Arguments[7] += `\other` }},
	} {
		t.Run(test.name, func(t *testing.T) {
			invocation := cloneInvocation(valid)
			test.mutate(&invocation)
			result, err := NewWindowsExecutor().Run(context.Background(), invocation, []byte(nativeToken))
			if result.Started || err == nil {
				t.Fatal("drifted native invocation reached process creation")
			}
		})
	}
}

func TestRegistrationEnvironmentContainsOnlyFixedBaseAndToken(t *testing.T) {
	block, err := registrationEnvironment(`C:\ProgramData\AgentWorkstationGateway-runner`, []byte(nativeToken))
	if err != nil {
		t.Fatal(err)
	}
	defer zeroUTF16(block)
	entries := strings.Split(strings.TrimRight(string(utf16.Decode(block)), "\x00"), "\x00")
	if len(entries) != 6 || entries[0] != TokenEnvironment+"="+nativeToken {
		t.Fatalf("unexpected isolated environment shape: %d", len(entries))
	}
	for _, entry := range entries[1:] {
		key := strings.SplitN(entry, "=", 2)[0]
		if key != "PATH" && key != "SystemDrive" && key != "SystemRoot" && key != "TEMP" && key != "TMP" {
			t.Fatalf("unexpected inherited environment entry: %s", key)
		}
	}
}

func nativeInvocation(t *testing.T, runnerName string) Invocation {
	t.Helper()
	root := filepath.Join(t.TempDir(), "runner")
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(filepath.Join(root, "_work"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "main.go")
	program := `package main
import (
    "fmt"
    "os"
    "strings"
    "time"
)
func main() {
    token := os.Getenv("ACTIONS_RUNNER_INPUT_TOKEN")
    if token != "synthetic-native-token-1" || os.Getenv("UNRELATED_AWG_SECRET") != "" {
        os.Exit(21)
    }
    for _, argument := range os.Args {
        if strings.Contains(argument, token) {
            os.Exit(22)
        }
    }
    if len(os.Args) != 13 || os.Args[1] != "configure" {
        os.Exit(23)
    }
    switch os.Args[6] {
    case "output-limit":
        fmt.Print(strings.Repeat("x", 2*1024*1024))
        time.Sleep(30*time.Second)
    case "deadline":
        time.Sleep(30*time.Second)
    default:
        fmt.Print(strings.Repeat("x", 1024))
        fmt.Fprint(os.Stderr, strings.Repeat("y", 1024))
    }
}
`
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(bin, "Runner.Listener.exe")
	command := exec.Command("go", "build", "-trimpath", "-o", executable, source)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("helper build failed: %v / %s", err, output)
	}
	repository, err := VerifyPrivateRepository("example/control-plane", true)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepare(strings.TrimSuffix(root, "-runner"), Request{
		Repository: repository, RunnerName: runnerName,
		RegistrationToken: []byte(nativeToken), RemovalToken: []byte("synthetic-native-remove-2"),
	})
	if err == nil && prepared.configure.WorkingDirectory == root {
		return prepared.configure
	}
	// The generic installer derives a -runner sibling. Native executor tests use
	// an isolated temp root directly, while preserving the exact invocation
	// contract enforced by validateInvocation.
	return Invocation{
		Executable: executable, WorkingDirectory: root, TokenEnvironment: TokenEnvironment,
		Arguments: []string{
			"configure", "--unattended", "--url", "https://github.com/example/control-plane",
			"--name", runnerName, "--work", filepath.Join(root, "_work"),
			"--disableupdate", "--no-default-labels", "--labels", RegistrationLabel,
		},
	}
}

func assertNativeExecutorRule(t *testing.T, err error, rule string) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Rule != rule {
		t.Fatalf("expected %s, got %T / %v", rule, err, err)
	}
}
