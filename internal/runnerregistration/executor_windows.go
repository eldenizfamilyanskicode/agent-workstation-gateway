//go:build windows

package runnerregistration

import (
	"context"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

const (
	maxRegistrationOutput = 1024 * 1024
	executorReapTimeout   = 10 * time.Second
	executorTerminated    = uint32(0xC000013A)
)

type WindowsExecutor struct{}

type executorPipes struct {
	stdinChild   windows.Handle
	stdinParent  windows.Handle
	stdoutChild  windows.Handle
	stdoutParent windows.Handle
	stderrChild  windows.Handle
	stderrParent windows.Handle
}

type waitResult struct {
	exitCode uint32
	err      error
}

type outputLimit struct {
	total    atomic.Int64
	exceeded chan struct{}
	once     sync.Once
}

func NewWindowsExecutor() *WindowsExecutor { return &WindowsExecutor{} }

func (*WindowsExecutor) Run(ctx context.Context, invocation Invocation, token []byte) (ProcessResult, error) {
	if ctx == nil || validateInvocation(invocation) != nil || !validToken(token) {
		return ProcessResult{}, registrationError("executor-input-invalid")
	}
	if err := validateExecutable(invocation.Executable); err != nil {
		return ProcessResult{}, err
	}
	application, commandLine, directory, err := nativeCommand(invocation)
	if err != nil {
		return ProcessResult{}, err
	}
	environment, err := registrationEnvironment(invocation.WorkingDirectory, token)
	if err != nil {
		return ProcessResult{}, err
	}
	defer zeroUTF16(environment)

	pipes, err := newExecutorPipes()
	if err != nil {
		return ProcessResult{}, err
	}
	defer pipes.closeAll()
	job, err := newExecutorJob()
	if err != nil {
		return ProcessResult{}, err
	}
	jobOwned := true
	defer func() {
		if jobOwned {
			_ = windows.CloseHandle(job)
		}
	}()

	handles := []windows.Handle{pipes.stdinChild, pipes.stdoutChild, pipes.stderrChild}
	attributes, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return ProcessResult{}, registrationError("executor-handle-list-failed")
	}
	defer attributes.Delete()
	if err := attributes.Update(
		windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
		unsafe.Pointer(&handles[0]),
		uintptr(len(handles))*unsafe.Sizeof(handles[0]),
	); err != nil {
		return ProcessResult{}, registrationError("executor-handle-policy-failed")
	}
	startup := windows.StartupInfoEx{}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	startup.Flags = windows.STARTF_USESTDHANDLES
	startup.StdInput = pipes.stdinChild
	startup.StdOutput = pipes.stdoutChild
	startup.StdErr = pipes.stderrChild
	startup.ProcThreadAttributeList = attributes.List()
	process := windows.ProcessInformation{}
	creationFlags := uint32(
		windows.CREATE_SUSPENDED | windows.CREATE_UNICODE_ENVIRONMENT |
			windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_NO_WINDOW |
			windows.CREATE_DEFAULT_ERROR_MODE,
	)
	if err := windows.CreateProcess(
		application, commandLine, nil, nil, true, creationFlags,
		&environment[0], directory, &startup.StartupInfo, &process,
	); err != nil {
		return ProcessResult{}, registrationError("executor-process-create-failed")
	}
	result := ProcessResult{Started: true}
	processOwned := true
	defer func() {
		if processOwned {
			_ = windows.TerminateProcess(process.Process, executorTerminated)
			_, _ = windows.WaitForSingleObject(process.Process, 5000)
			_ = windows.CloseHandle(process.Thread)
			_ = windows.CloseHandle(process.Process)
		}
	}()
	if err := windows.AssignProcessToJobObject(job, process.Process); err != nil {
		return result, registrationError("executor-job-assignment-failed")
	}
	pipes.closeChildEnds()
	stdin := takeExecutorFile(&pipes.stdinParent, "awg-runner-stdin")
	stdout := takeExecutorFile(&pipes.stdoutParent, "awg-runner-stdout")
	stderr := takeExecutorFile(&pipes.stderrParent, "awg-runner-stderr")
	if stdin == nil || stdout == nil || stderr == nil {
		closeExecutorFiles(stdin, stdout, stderr)
		return result, registrationError("executor-pipe-conversion-failed")
	}
	_ = stdin.Close()
	limit := &outputLimit{exceeded: make(chan struct{})}
	var drains sync.WaitGroup
	drains.Add(2)
	go drainExecutorOutput(stdout, limit, &drains)
	go drainExecutorOutput(stderr, limit, &drains)
	if _, err := windows.ResumeThread(process.Thread); err != nil {
		_ = windows.CloseHandle(process.Thread)
		process.Thread = 0
		_ = windows.TerminateJobObject(job, executorTerminated)
		drains.Wait()
		return result, registrationError("executor-process-resume-failed")
	}
	if err := windows.CloseHandle(process.Thread); err != nil {
		_ = windows.TerminateJobObject(job, executorTerminated)
		drains.Wait()
		return result, registrationError("executor-thread-close-failed")
	}
	process.Thread = 0

	wait := make(chan waitResult, 1)
	go func() {
		event, waitErr := windows.WaitForSingleObject(process.Process, windows.INFINITE)
		var exitCode uint32
		if waitErr != nil || event != windows.WAIT_OBJECT_0 {
			wait <- waitResult{err: registrationError("executor-process-wait-failed")}
			return
		}
		if err := windows.GetExitCodeProcess(process.Process, &exitCode); err != nil {
			wait <- waitResult{err: registrationError("executor-exit-query-failed")}
			return
		}
		wait <- waitResult{exitCode: exitCode}
	}()

	var outcome waitResult
	var boundaryErr error
	select {
	case outcome = <-wait:
	case <-ctx.Done():
		boundaryErr = registrationError("executor-context-cancelled")
		_ = windows.TerminateJobObject(job, executorTerminated)
		outcome = awaitExecutorReap(wait)
	case <-limit.exceeded:
		boundaryErr = registrationError("executor-output-limit")
		_ = windows.TerminateJobObject(job, executorTerminated)
		outcome = awaitExecutorReap(wait)
	}
	// Closing the kill-on-close job prevents a successful root process from
	// leaving configuration helpers behind with inherited token material.
	_ = windows.TerminateJobObject(job, executorTerminated)
	if err := windows.CloseHandle(job); err != nil && boundaryErr == nil {
		boundaryErr = registrationError("executor-job-close-failed")
	}
	jobOwned = false
	drains.Wait()
	if err := windows.CloseHandle(process.Process); err != nil && boundaryErr == nil {
		boundaryErr = registrationError("executor-process-close-failed")
	}
	process.Process = 0
	processOwned = false
	if outcome.err != nil && boundaryErr == nil {
		boundaryErr = outcome.err
	}
	if boundaryErr != nil {
		return result, boundaryErr
	}
	result.ExitCode = int(outcome.exitCode)
	return result, nil
}

func validateInvocation(invocation Invocation) error {
	if invocation.TokenEnvironment != TokenEnvironment ||
		platformpath.ValidateAbsolute(platformpath.Windows, invocation.WorkingDirectory) != nil ||
		platformpath.ValidateAbsolute(platformpath.Windows, invocation.Executable) != nil ||
		!platformpath.Contains(platformpath.Windows, invocation.WorkingDirectory, invocation.Executable) ||
		!strings.EqualFold(invocation.Executable, invocation.WorkingDirectory+`\bin\Runner.Listener.exe`) {
		return registrationError("executor-invocation-denied")
	}
	for _, argument := range invocation.Arguments {
		if argument == "" || strings.ContainsRune(argument, 0) {
			return registrationError("executor-argument-invalid")
		}
	}
	if len(invocation.Arguments) == 1 && invocation.Arguments[0] == "remove" {
		return nil
	}
	if len(invocation.Arguments) != 12 || invocation.Arguments[0] != "configure" ||
		invocation.Arguments[1] != "--unattended" || invocation.Arguments[2] != "--url" ||
		invocation.Arguments[4] != "--name" || !runnerNamePattern.MatchString(invocation.Arguments[5]) ||
		invocation.Arguments[6] != "--work" ||
		!platformpath.Equal(platformpath.Windows, invocation.Arguments[7], invocation.WorkingDirectory+`\_work`) ||
		invocation.Arguments[8] != "--disableupdate" || invocation.Arguments[9] != "--no-default-labels" ||
		invocation.Arguments[10] != "--labels" || invocation.Arguments[11] != RegistrationLabel {
		return registrationError("executor-configure-shape-denied")
	}
	repository := strings.TrimPrefix(invocation.Arguments[3], "https://github.com/")
	receipt, err := VerifyPrivateRepository(repository, true)
	if err != nil || invocation.Arguments[3] != receipt.url {
		return registrationError("executor-repository-denied")
	}
	return nil
}

func validateExecutable(path string) error {
	information, err := os.Lstat(path)
	if err != nil || !information.Mode().IsRegular() || information.Size() <= 0 ||
		information.Size() > 256*1024*1024 {
		return registrationError("executor-listener-invalid")
	}
	return nil
}

func nativeCommand(invocation Invocation) (*uint16, *uint16, *uint16, error) {
	application, err := windows.UTF16PtrFromString(invocation.Executable)
	if err != nil {
		return nil, nil, nil, registrationError("executor-path-invalid")
	}
	command := syscall.EscapeArg(invocation.Executable)
	for _, argument := range invocation.Arguments {
		command += " " + syscall.EscapeArg(argument)
	}
	commandLine, err := windows.UTF16PtrFromString(command)
	if err != nil {
		return nil, nil, nil, registrationError("executor-command-invalid")
	}
	directory, err := windows.UTF16PtrFromString(invocation.WorkingDirectory)
	if err != nil {
		return nil, nil, nil, registrationError("executor-directory-invalid")
	}
	return application, commandLine, directory, nil
}

func registrationEnvironment(runnerRoot string, token []byte) ([]uint16, error) {
	windowsRoot, err := windows.GetWindowsDirectory()
	if err != nil || platformpath.ValidateAbsolute(platformpath.Windows, windowsRoot) != nil || len(windowsRoot) < 3 {
		return nil, registrationError("executor-windows-root-invalid")
	}
	entries := []struct{ key, value string }{
		{"PATH", windowsRoot + `\System32`},
		{"SystemDrive", windowsRoot[:2]},
		{"SystemRoot", windowsRoot},
		{"TEMP", runnerRoot + `\_work`},
		{"TMP", runnerRoot + `\_work`},
	}
	block := make([]uint16, 0, len(token)+512)
	block = appendStringEntry(block, TokenEnvironment, "")
	block = block[:len(block)-1]
	for _, value := range token {
		block = append(block, uint16(value))
	}
	block = append(block, 0)
	for _, entry := range entries {
		block = appendStringEntry(block, entry.key, entry.value)
	}
	block = append(block, 0)
	return block, nil
}

func appendStringEntry(block []uint16, key, value string) []uint16 {
	encoded := utf16.Encode([]rune(key + "=" + value))
	block = append(block, encoded...)
	return append(block, 0)
}

func newExecutorPipes() (*executorPipes, error) {
	pipes := &executorPipes{}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	if err := windows.CreatePipe(&pipes.stdinChild, &pipes.stdinParent, &attributes, 0); err != nil {
		return nil, registrationError("executor-stdin-pipe-failed")
	}
	if err := windows.SetHandleInformation(pipes.stdinParent, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		pipes.closeAll()
		return nil, registrationError("executor-stdin-policy-failed")
	}
	if err := windows.CreatePipe(&pipes.stdoutParent, &pipes.stdoutChild, &attributes, 0); err != nil {
		pipes.closeAll()
		return nil, registrationError("executor-stdout-pipe-failed")
	}
	if err := windows.SetHandleInformation(pipes.stdoutParent, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		pipes.closeAll()
		return nil, registrationError("executor-stdout-policy-failed")
	}
	if err := windows.CreatePipe(&pipes.stderrParent, &pipes.stderrChild, &attributes, 0); err != nil {
		pipes.closeAll()
		return nil, registrationError("executor-stderr-pipe-failed")
	}
	if err := windows.SetHandleInformation(pipes.stderrParent, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		pipes.closeAll()
		return nil, registrationError("executor-stderr-policy-failed")
	}
	return pipes, nil
}

func newExecutorJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, registrationError("executor-job-create-failed")
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(
		job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)),
	); err != nil {
		_ = windows.CloseHandle(job)
		return 0, registrationError("executor-job-policy-failed")
	}
	return job, nil
}

func (pipes *executorPipes) closeChildEnds() {
	closeExecutorHandle(&pipes.stdinChild)
	closeExecutorHandle(&pipes.stdoutChild)
	closeExecutorHandle(&pipes.stderrChild)
}

func (pipes *executorPipes) closeAll() {
	closeExecutorHandle(&pipes.stdinChild)
	closeExecutorHandle(&pipes.stdinParent)
	closeExecutorHandle(&pipes.stdoutChild)
	closeExecutorHandle(&pipes.stdoutParent)
	closeExecutorHandle(&pipes.stderrChild)
	closeExecutorHandle(&pipes.stderrParent)
}

func takeExecutorFile(handle *windows.Handle, name string) *os.File {
	if *handle == 0 || *handle == windows.InvalidHandle {
		return nil
	}
	file := os.NewFile(uintptr(*handle), name)
	*handle = 0
	return file
}

func closeExecutorHandle(handle *windows.Handle) {
	if *handle != 0 && *handle != windows.InvalidHandle {
		_ = windows.CloseHandle(*handle)
	}
	*handle = 0
}

func closeExecutorFiles(files ...*os.File) {
	for _, file := range files {
		if file != nil {
			_ = file.Close()
		}
	}
}

func drainExecutorOutput(source *os.File, limit *outputLimit, wait *sync.WaitGroup) {
	defer wait.Done()
	defer source.Close()
	_, _ = io.Copy(limit, source)
}

func (limit *outputLimit) Write(content []byte) (int, error) {
	if limit.total.Add(int64(len(content))) > maxRegistrationOutput {
		limit.once.Do(func() { close(limit.exceeded) })
	}
	return len(content), nil
}

func awaitExecutorReap(wait <-chan waitResult) waitResult {
	timer := time.NewTimer(executorReapTimeout)
	defer timer.Stop()
	select {
	case result := <-wait:
		return result
	case <-timer.C:
		return waitResult{err: registrationError("executor-reap-timeout")}
	}
}

//go:noinline
func zeroUTF16(buffer []uint16) {
	for index := range buffer {
		buffer[index] = 0
	}
	runtime.KeepAlive(buffer)
}

var _ Executor = (*WindowsExecutor)(nil)
