//go:build linux

package process

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionpolicy"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionrun"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/shellinvoke"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == HelperOperation {
		os.Exit(RunHelper(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func TestLauncherDropsIdentityCapabilitiesAndSupplementaryGroups(t *testing.T) {
	requireRoot(t)
	working := writableDirectory(t)
	invocation := bashInvocation(t, "printf 'uid=%s\\ngid=%s\\ngroups=%s\\n' \"$(id -u)\" \"$(id -g)\" \"$(id -G)\"; awk '/^CapEff:|^NoNewPrivs:/{print}' /proc/self/status")
	launcher, err := NewLauncher()
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	process, err := launcher.Start(context.Background(), nativeLaunch(working, invocation), &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	exit := <-process.Exit()
	output := stdout.String()
	for _, expected := range []string{"uid=65534", "gid=65534", "groups=65534", "CapEff:\t0000000000000000", "NoNewPrivs:\t1"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("missing %q in %q (stderr %q)", expected, output, stderr.String())
		}
	}
	if exit.Code != 0 || exit.RuntimeError != nil {
		t.Fatalf("unexpected exit: %#v", exit)
	}
}

func TestTerminateTreeKillsAndReapsProcessGroup(t *testing.T) {
	requireRoot(t)
	if err := EnableChildSubreaper(); err != nil {
		t.Fatal(err)
	}
	working := writableDirectory(t)
	invocation := bashInvocation(t, "sleep 30 & child=$!; printf '%s' \"$child\" > child.pid; wait")
	launcher, _ := NewLauncher()
	process, err := launcher.Start(context.Background(), nativeLaunch(working, invocation), &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	pidPath := filepath.Join(working, "child.pid")
	var childPID int
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		encoded, readErr := os.ReadFile(pidPath)
		if readErr == nil {
			childPID, _ = strconv.Atoi(string(encoded))
			if childPID > 0 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if childPID <= 0 {
		t.Fatal("child process was not observed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := process.TerminateTree(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", childPID)); !os.IsNotExist(err) {
		t.Fatalf("child process %d survived or was not reaped", childPID)
	}
}

func nativeLaunch(working string, invocation shellinvoke.Invocation) executionrun.NativeLaunch {
	identity := installconfig.Principal{Name: "awg-exec", Identifier: "uid:65534", PrimaryGroupIdentifier: "gid:65534"}
	return executionrun.NativeLaunch{ExecutionIdentity: identity, WorkingDirectory: working, ApprovedRoot: working,
		Environment: []string{"PATH=/usr/bin:/bin", "HOME=" + working, "TMPDIR=" + working}, Invocation: invocation, Capabilities: []installconfig.Capability{}}
}

func bashInvocation(t *testing.T, script string) shellinvoke.Invocation {
	t.Helper()
	invocation, err := shellinvoke.Build(executionpolicy.LaunchPlan{Shell: v1.ShellBash, Executable: "/bin/bash", Script: script})
	if err != nil {
		t.Fatal(err)
	}
	return invocation
}

func writableDirectory(t *testing.T) string {
	t.Helper()
	path, err := os.MkdirTemp("", "awg-process-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(path) })
	if err := os.Chmod(path, 0o777); err != nil {
		t.Fatal(err)
	}
	return path
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root to verify the native identity boundary")
	}
}
