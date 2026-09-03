//go:build linux

package process

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionrun"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/linux/pathresolver"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

const HelperOperation = "__linux-exec"

type Error struct{ Rule string }

func (failure *Error) Error() string {
	return fmt.Sprintf("Linux process boundary failed: %s", failure.Rule)
}

type Launcher struct{}

type nativeProcess struct {
	command *exec.Cmd
	pgid    int
	exit    chan executionrun.ProcessExit
	done    chan struct{}
	once    sync.Once
}

func NewLauncher() (*Launcher, error) {
	if os.Geteuid() != 0 {
		return nil, processError("root-broker-required")
	}
	return &Launcher{}, nil
}

func (*Launcher) Start(ctx context.Context, launch executionrun.NativeLaunch, stdout io.Writer, stderr io.Writer) (executionrun.Process, error) {
	if ctx == nil || stdout == nil || stderr == nil || len(launch.Capabilities) != 0 {
		return nil, processError("launch-input-denied")
	}
	uid, gid, err := PrincipalIDs(launch.ExecutionIdentity)
	if err != nil {
		return nil, err
	}
	resolution, err := (pathresolver.Resolver{}).ResolveWithin(ctx, platformpath.Linux, launch.WorkingDirectory, []string{launch.ApprovedRoot})
	if err != nil || resolution.WorkingDirectory != launch.WorkingDirectory {
		return nil, processError("working-directory-denied")
	}
	if err := validateExecutable(launch.Invocation.Executable()); err != nil {
		return nil, err
	}
	helper := "/proc/self/exe"
	arguments := []string{HelperOperation, strconv.FormatUint(uint64(uid), 10), strconv.FormatUint(uint64(gid), 10), launch.Invocation.Executable()}
	arguments = append(arguments, launch.Invocation.Arguments()...)
	command := exec.Command(helper, arguments...)
	command.Dir = resolution.WorkingDirectory
	command.Env = append([]string(nil), launch.Environment...)
	command.Stdout = stdout
	command.Stderr = stderr
	command.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}},
		Setpgid:    true,
		Pdeathsig:  syscall.SIGKILL,
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, processError("stdin-pipe-failed")
	}
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		return nil, processError("restricted-process-create-failed")
	}
	pgid, err := unix.Getpgid(command.Process.Pid)
	if err != nil || pgid != command.Process.Pid {
		_ = unix.Kill(-command.Process.Pid, unix.SIGKILL)
		_ = command.Wait()
		return nil, processError("process-group-verification-failed")
	}
	process := &nativeProcess{command: command, pgid: pgid, exit: make(chan executionrun.ProcessExit, 1), done: make(chan struct{})}
	go func() {
		_, copyErr := io.Copy(stdin, launch.Invocation.ScriptReader())
		closeErr := stdin.Close()
		if copyErr != nil || closeErr != nil {
			_ = unix.Kill(-pgid, unix.SIGKILL)
		}
	}()
	go process.wait()
	return process, nil
}

func (process *nativeProcess) Exit() <-chan executionrun.ProcessExit { return process.exit }

func (process *nativeProcess) TerminateTree(ctx context.Context) error {
	if process == nil || process.command == nil || ctx == nil {
		return processError("termination-input-invalid")
	}
	select {
	case <-process.done:
		return nil
	default:
	}
	if err := unix.Kill(-process.pgid, unix.SIGTERM); err != nil && !errors.Is(err, unix.ESRCH) {
		return processError("sigterm-failed")
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-process.done:
		return nil
	case <-ctx.Done():
		_ = unix.Kill(-process.pgid, unix.SIGKILL)
		return processError("termination-deadline")
	case <-timer.C:
	}
	if err := unix.Kill(-process.pgid, unix.SIGKILL); err != nil && !errors.Is(err, unix.ESRCH) {
		return processError("sigkill-failed")
	}
	select {
	case <-process.done:
		return nil
	case <-ctx.Done():
		return processError("reap-deadline")
	}
}

func (process *nativeProcess) wait() {
	err := process.command.Wait()
	_ = unix.Kill(-process.pgid, unix.SIGKILL)
	reapProcessGroup(process.pgid)
	result := executionrun.ProcessExit{}
	if err == nil {
		result.Code = 0
	} else {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			status, ok := exitError.Sys().(syscall.WaitStatus)
			if !ok {
				result.RuntimeError = processError("exit-status-invalid")
			} else if status.Signaled() {
				result.Code = int64(128 + status.Signal())
			} else {
				result.Code = int64(status.ExitStatus())
			}
		} else {
			result.RuntimeError = processError("process-wait-failed")
		}
	}
	process.once.Do(func() {
		process.exit <- result
		close(process.exit)
		close(process.done)
	})
}

func RunHelper(args []string) int {
	if len(args) < 4 || args[0] != HelperOperation {
		return 64
	}
	if !PrepareHelperIdentity(args[1], args[2]) {
		return 70
	}
	executable := args[3]
	if platformpath.ValidateAbsolute(platformpath.Linux, executable) != nil {
		return 64
	}
	argv := append([]string{executable}, args[4:]...)
	if err := unix.Exec(executable, argv, os.Environ()); err != nil {
		return 126
	}
	return 0
}

func EnableChildSubreaper() error {
	if os.Geteuid() != 0 {
		return processError("root-broker-required")
	}
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return processError("subreaper-enable-failed")
	}
	return nil
}

func PrincipalIDs(principal installconfig.Principal) (uint32, uint32, error) {
	uid, err := parseID(principal.Identifier, "uid:")
	if err != nil {
		return 0, 0, processError("execution-uid-invalid")
	}
	gid, err := parseID(principal.PrimaryGroupIdentifier, "gid:")
	if err != nil {
		return 0, 0, processError("execution-gid-invalid")
	}
	return uid, gid, nil
}

func PrepareHelperIdentity(uidText, gidText string) bool {
	uid, uidErr := strconv.ParseUint(uidText, 10, 32)
	gid, gidErr := strconv.ParseUint(gidText, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 ||
		os.Getuid() != int(uid) || os.Geteuid() != int(uid) || os.Getgid() != int(gid) || os.Getegid() != int(gid) {
		return false
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 || !capabilitiesEmpty() {
		return false
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return false
	}
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) == nil && noNewPrivilegesSet()
}

func parseID(value, prefix string) (uint32, error) {
	if !strings.HasPrefix(value, prefix) {
		return 0, processError("identity-invalid")
	}
	parsed, err := strconv.ParseUint(strings.TrimPrefix(value, prefix), 10, 32)
	if err != nil || parsed == 0 || parsed == 4294967295 {
		return 0, processError("identity-invalid")
	}
	return uint32(parsed), nil
}

func validateExecutable(path string) error {
	if platformpath.ValidateAbsolute(platformpath.Linux, path) != nil {
		return processError("executable-path-invalid")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return processError("executable-invalid")
	}
	return nil
}

func capabilitiesEmpty() bool {
	file, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	seen := 0
	for scanner.Scan() {
		line := scanner.Text()
		for _, name := range []string{"CapInh:", "CapPrm:", "CapEff:", "CapAmb:"} {
			if strings.HasPrefix(line, name) {
				seen++
				if strings.TrimSpace(strings.TrimPrefix(line, name)) != "0000000000000000" {
					return false
				}
			}
		}
	}
	return scanner.Err() == nil && seen == 4
}

func noNewPrivilegesSet() bool {
	encoded, err := os.ReadFile("/proc/self/status")
	return err == nil && strings.Contains(string(encoded), "NoNewPrivs:\t1")
}

func reapProcessGroup(pgid int) {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var status unix.WaitStatus
		_, err := unix.Wait4(-pgid, &status, unix.WNOHANG, nil)
		if errors.Is(err, unix.ECHILD) {
			return
		}
		if err != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func processError(rule string) error { return &Error{Rule: rule} }

var _ executionrun.Launcher = (*Launcher)(nil)
var _ executionrun.Process = (*nativeProcess)(nil)
