//go:build windows

package process

import (
	"context"
	"io"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionrun"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/pathresolver"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

type Launcher struct {
	tokens TokenSource
}

var _ executionrun.Launcher = (*Launcher)(nil)

func NewLauncher(tokens TokenSource) (*Launcher, error) {
	if tokens == nil {
		return nil, boundaryError("token-source-required")
	}
	return &Launcher{tokens: tokens}, nil
}

func (launcher *Launcher) Start(
	ctx context.Context,
	launch executionrun.NativeLaunch,
	stdout io.Writer,
	stderr io.Writer,
) (executionrun.Process, error) {
	if ctx == nil || stdout == nil || stderr == nil {
		return nil, boundaryError("launch-input-required")
	}
	resolution, err := (pathresolver.Resolver{}).ResolveWithin(
		ctx, platformpath.Windows, launch.WorkingDirectory, []string{launch.ApprovedRoot},
	)
	if err != nil || !platformpath.Equal(platformpath.Windows, resolution.WorkingDirectory, launch.WorkingDirectory) {
		return nil, boundaryError("working-directory-denied")
	}
	lease, err := launcher.tokens.Acquire(ctx, launch.ExecutionIdentity)
	if err != nil || lease == nil {
		return nil, boundaryError("execution-token-unavailable")
	}
	leaseOwned := true
	defer func() {
		if leaseOwned {
			_ = lease.Close()
		}
	}()
	if err := validateTokenIdentity(lease.Token(), launch.ExecutionIdentity); err != nil {
		return nil, err
	}
	executable, commandLine, err := buildCommandLine(launch.Invocation)
	if err != nil {
		return nil, err
	}
	environment, err := buildEnvironmentBlock(launch.Environment)
	if err != nil {
		return nil, err
	}
	workingDirectory, err := windows.UTF16PtrFromString(resolution.WorkingDirectory)
	if err != nil {
		return nil, boundaryError("invalid-working-directory")
	}
	pipes, err := newProcessPipes()
	if err != nil {
		return nil, err
	}
	defer pipes.closeAll()
	job, err := newJobObject()
	if err != nil {
		return nil, err
	}
	jobOwned := true
	defer func() {
		if jobOwned {
			_ = job.close()
		}
	}()

	handles := pipes.childHandles()
	attributes, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return nil, boundaryError("handle-list-create-failed")
	}
	defer attributes.Delete()
	if err := attributes.Update(
		windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
		unsafe.Pointer(&handles[0]),
		uintptr(len(handles))*unsafe.Sizeof(handles[0]),
	); err != nil {
		return nil, boundaryError("handle-list-policy-failed")
	}
	startup := windows.StartupInfoEx{}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	startup.Flags = windows.STARTF_USESTDHANDLES
	startup.StdInput = pipes.stdinChild
	startup.StdOutput = pipes.stdoutChild
	startup.StdErr = pipes.stderrChild
	startup.ProcThreadAttributeList = attributes.List()
	processInformation := windows.ProcessInformation{}
	creationFlags := uint32(
		windows.CREATE_SUSPENDED |
			windows.CREATE_UNICODE_ENVIRONMENT |
			windows.EXTENDED_STARTUPINFO_PRESENT |
			windows.CREATE_NO_WINDOW |
			windows.CREATE_DEFAULT_ERROR_MODE,
	)
	if err := windows.CreateProcessAsUser(
		lease.Token(), executable, commandLine, nil, nil, true, creationFlags,
		&environment[0], workingDirectory, &startup.StartupInfo, &processInformation,
	); err != nil {
		return nil, boundaryError("restricted-process-create-failed")
	}
	pipes.closeChildEnds()
	processCreated := true
	defer func() {
		if processCreated {
			_ = windows.TerminateProcess(processInformation.Process, terminatedExitCode)
			_, _ = windows.WaitForSingleObject(processInformation.Process, 5000)
			_ = windows.CloseHandle(processInformation.Thread)
			_ = windows.CloseHandle(processInformation.Process)
		}
	}()
	if err := job.assign(processInformation.Process); err != nil {
		return nil, err
	}
	stdin, stdoutPipe, stderrPipe, err := pipes.parentFiles()
	if err != nil {
		_ = job.terminate()
		return nil, err
	}
	native := &nativeProcess{
		job: job, process: processInformation.Process, lease: lease,
		stdin: stdin, stdout: stdoutPipe, stderr: stderrPipe,
		stdoutSink: stdout, stderrSink: stderr, script: launch.Invocation.ScriptReader(),
		exit: make(chan executionrun.ProcessExit, 1), done: make(chan struct{}),
	}
	native.start()
	if _, err := windows.ResumeThread(processInformation.Thread); err != nil {
		_ = windows.CloseHandle(processInformation.Thread)
		processInformation.Thread = 0
		processCreated = false
		jobOwned = false
		leaseOwned = false
		cleanupContext, cancel := context.WithTimeout(context.Background(), nativeReapLimit)
		_ = native.TerminateTree(cleanupContext)
		cancel()
		return nil, boundaryError("restricted-process-resume-failed")
	}
	if err := windows.CloseHandle(processInformation.Thread); err != nil {
		processInformation.Thread = 0
		processCreated = false
		jobOwned = false
		leaseOwned = false
		cleanupContext, cancel := context.WithTimeout(context.Background(), nativeReapLimit)
		_ = native.TerminateTree(cleanupContext)
		cancel()
		return nil, boundaryError("thread-handle-close-failed")
	}
	processInformation.Thread = 0
	processCreated = false
	jobOwned = false
	leaseOwned = false
	return native, nil
}
