//go:build windows

package process

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionpolicy"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionrun"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/pathresolver"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/shellinvoke"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

const helperModeEnvironment = "AWG_TEST_JOB_HELPER_MODE"
const helperPIDFileEnvironment = "AWG_TEST_JOB_HELPER_PID_FILE"

type currentTokenLease struct {
	closed bool
}

func (*currentTokenLease) Token() windows.Token { return windows.GetCurrentProcessToken() }
func (lease *currentTokenLease) Close() error {
	lease.closed = true
	return nil
}

type fixedTokenSource struct {
	lease *currentTokenLease
	calls int
}

func (source *fixedTokenSource) Acquire(context.Context, installconfig.Principal) (TokenLease, error) {
	source.calls++
	return source.lease, nil
}

func TestValidateTokenIdentityMatchesUserAndPrimaryGroup(t *testing.T) {
	token := windows.GetCurrentProcessToken()
	principal := principalForToken(t, token)
	if err := validateTokenIdentity(token, principal); err != nil {
		t.Fatal(err)
	}
	principal.Identifier = "S-1-5-21-1000-1000-1000-4242"
	err := validateTokenIdentity(token, principal)
	assertBoundaryRule(t, err, "token-user-mismatch")
	if strings.Contains(err.Error(), principal.Identifier) {
		t.Fatal("token mismatch error echoed identity data")
	}
}

func TestCommandLineNeverContainsScriptData(t *testing.T) {
	marker := "SYNTHETIC-SCRIPT-MARKER-7f0d"
	invocation, err := shellinvoke.Build(executionpolicy.LaunchPlan{
		Shell: v1.ShellPwsh, Executable: `C:\Program Files\PowerShell\7\pwsh.exe`, Script: marker + "\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	executable, commandLine, err := buildCommandLine(invocation)
	if err != nil {
		t.Fatal(err)
	}
	trusted := windows.UTF16PtrToString(executable) + "\x00" + windows.UTF16PtrToString(commandLine)
	if strings.Contains(trusted, marker) {
		t.Fatal("request script reached the trusted Windows command line")
	}
	script, err := io.ReadAll(invocation.ScriptReader())
	if err != nil || string(script) != marker+"\n" {
		t.Fatalf("script stdin changed: %q / %v", script, err)
	}
}

func TestEnvironmentBlockSortsAndRejectsAmbiguity(t *testing.T) {
	block, err := buildEnvironmentBlock([]string{"Path=C:\\Tools", "AWG_REQUEST_ID=req-1"})
	if err != nil {
		t.Fatal(err)
	}
	decoded := string(utf16.Decode(block[:len(block)-2]))
	if !strings.HasPrefix(decoded, "AWG_REQUEST_ID=req-1\x00Path=C:\\Tools") || block[len(block)-1] != 0 || block[len(block)-2] != 0 {
		t.Fatal("environment block is not sorted and double-NUL terminated")
	}
	for _, environment := range [][]string{{"MISSING"}, {"Path=one", "PATH=two"}, {"A=ok\x00bad"}} {
		if _, err := buildEnvironmentBlock(environment); err == nil {
			t.Fatal("ambiguous environment was accepted")
		}
	}
}

func TestLauncherRejectsMismatchedTokenWithoutFallback(t *testing.T) {
	root := nativeTestDirectory(t, t.TempDir())
	principal := principalForToken(t, windows.GetCurrentProcessToken())
	principal.Identifier = "S-1-5-21-1000-1000-1000-4242"
	lease := &currentTokenLease{}
	source := &fixedTokenSource{lease: lease}
	launcher, err := NewLauncher(source)
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := shellinvoke.Build(executionpolicy.LaunchPlan{
		Shell: v1.ShellCmd, Executable: `C:\Windows\System32\cmd.exe`, Script: "echo synthetic\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = launcher.Start(context.Background(), executionrun.NativeLaunch{
		ExecutionIdentity: principal, WorkingDirectory: root, ApprovedRoot: root,
		Environment: []string{`SystemRoot=C:\Windows`}, Invocation: invocation,
	}, io.Discard, io.Discard)
	assertBoundaryRule(t, err, "token-user-mismatch")
	if source.calls != 1 || !lease.closed {
		t.Fatal("rejected token lease was not closed exactly at the launch boundary")
	}
}

func TestJobObjectTerminatesDescendantTree(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	environment, err := buildEnvironmentBlock(helperEnvironment("parent", pidFile))
	if err != nil {
		t.Fatal(err)
	}
	executablePointer, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		t.Fatal(err)
	}
	commandLinePointer, err := windows.UTF16PtrFromString(windows.ComposeCommandLine([]string{executable, "-test.run=TestJobObjectHelper"}))
	if err != nil {
		t.Fatal(err)
	}
	job, err := newJobObject()
	if err != nil {
		t.Fatal(err)
	}
	defer job.close()
	startup := windows.StartupInfo{}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	information := windows.ProcessInformation{}
	if err := windows.CreateProcess(
		executablePointer, commandLinePointer, nil, nil, false,
		windows.CREATE_SUSPENDED|windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NO_WINDOW,
		&environment[0], nil, &startup, &information,
	); err != nil {
		t.Fatal("could not create native Job Object test process")
	}
	defer windows.CloseHandle(information.Process)
	if err := job.assign(information.Process); err != nil {
		_ = windows.TerminateProcess(information.Process, terminatedExitCode)
		t.Fatal(err)
	}
	if _, err := windows.ResumeThread(information.Thread); err != nil {
		_ = windows.TerminateProcess(information.Process, terminatedExitCode)
		t.Fatal(err)
	}
	_ = windows.CloseHandle(information.Thread)

	childPID := waitForChildPID(t, pidFile)
	child, err := windows.OpenProcess(windows.SYNCHRONIZE, false, childPID)
	if err != nil {
		t.Fatal("could not open native Job Object child process")
	}
	defer windows.CloseHandle(child)
	terminationContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := job.terminateAndWait(terminationContext); err != nil {
		t.Fatal(err)
	}
	assertProcessSignalled(t, information.Process)
	assertProcessSignalled(t, child)
}

func TestJobObjectHelper(t *testing.T) {
	switch os.Getenv(helperModeEnvironment) {
	case "parent":
		executable, err := os.Executable()
		if err != nil {
			os.Exit(2)
		}
		child := exec.Command(executable, "-test.run=TestJobObjectHelper")
		child.Env = helperEnvironment("child", "")
		if err := child.Start(); err != nil {
			os.Exit(3)
		}
		pidFile := os.Getenv(helperPIDFileEnvironment)
		if err := os.WriteFile(pidFile, []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
			os.Exit(4)
		}
		time.Sleep(time.Minute)
	case "child":
		time.Sleep(time.Minute)
	}
}

func helperEnvironment(mode string, pidFile string) []string {
	environment := []string{
		"SystemRoot=" + os.Getenv("SystemRoot"), "WINDIR=" + os.Getenv("WINDIR"),
		"TEMP=" + os.Getenv("TEMP"), "TMP=" + os.Getenv("TMP"), helperModeEnvironment + "=" + mode,
	}
	if pidFile != "" {
		environment = append(environment, helperPIDFileEnvironment+"="+pidFile)
	}
	return environment
}

func waitForChildPID(t *testing.T, pidFile string) uint32 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		content, err := os.ReadFile(pidFile)
		if err == nil {
			pid, parseErr := strconv.ParseUint(string(content), 10, 32)
			if parseErr != nil {
				t.Fatal("native Job Object helper wrote an invalid PID")
			}
			return uint32(pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("native Job Object helper did not create its descendant")
	return 0
}

func assertProcessSignalled(t *testing.T, handle windows.Handle) {
	t.Helper()
	event, err := windows.WaitForSingleObject(handle, 5000)
	if err != nil || event != windows.WAIT_OBJECT_0 {
		t.Fatal("Job Object process remained active after whole-tree termination")
	}
}

func nativeTestDirectory(t *testing.T, directory string) string {
	t.Helper()
	absolute, err := filepath.Abs(directory)
	if err != nil {
		t.Fatal(err)
	}
	absolute = filepath.Clean(absolute)
	if len(absolute) >= 2 && absolute[1] == ':' {
		absolute = strings.ToUpper(absolute[:1]) + absolute[1:]
	}
	resolution, err := (pathresolver.Resolver{}).ResolveWithin(context.Background(), platformpath.Windows, absolute, []string{absolute})
	if err == nil {
		return resolution.WorkingDirectory
	}
	// A hosted runner temp directory may itself be an alias. Resolve it with
	// the same handle primitive, then authorize the handle-canonical path.
	native, nativeErr := resolveNativeTestDirectory(absolute)
	if nativeErr != nil {
		t.Fatal("could not obtain native test directory")
	}
	return native
}

func resolveNativeTestDirectory(directory string) (string, error) {
	// Keep test fixture canonicalization in the resolver package boundary by
	// opening the directory as its own approved root after evaluating symlinks.
	evaluated, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return "", err
	}
	if len(evaluated) >= 2 && evaluated[1] == ':' {
		evaluated = strings.ToUpper(evaluated[:1]) + evaluated[1:]
	}
	return evaluated, nil
}

func principalForToken(t *testing.T, token windows.Token) installconfig.Principal {
	t.Helper()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal("could not query test token user")
	}
	group, err := token.GetTokenPrimaryGroup()
	if err != nil {
		t.Fatal("could not query test token primary group")
	}
	return installconfig.Principal{Name: "synthetic-test", Identifier: user.User.Sid.String(), PrimaryGroupIdentifier: group.PrimaryGroup.String()}
}

func assertBoundaryRule(t *testing.T, err error, rule string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected boundary rule %q", rule)
	}
	var failure *Error
	if !errors.As(err, &failure) || failure.Rule != rule {
		t.Fatalf("expected boundary rule %q, got %T / %v", rule, err, err)
	}
}
