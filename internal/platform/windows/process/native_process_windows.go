//go:build windows

package process

import (
	"context"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionrun"
)

const nativeReapLimit = 10 * time.Second

type nativeProcess struct {
	job         *jobObject
	process     windows.Handle
	lease       TokenLease
	stdin       *os.File
	stdout      *os.File
	stderr      *os.File
	stdoutSink  io.Writer
	stderrSink  io.Writer
	script      io.Reader
	exit        chan executionrun.ProcessExit
	done        chan struct{}
	ioWait      sync.WaitGroup
	errorMu     sync.Mutex
	runtimeFail bool
}

var _ executionrun.Process = (*nativeProcess)(nil)

func (process *nativeProcess) start() {
	process.ioWait.Add(3)
	go func() {
		defer process.ioWait.Done()
		_, _ = io.Copy(process.stdin, process.script)
		_ = process.stdin.Close()
	}()
	go process.drain(process.stdout, process.stdoutSink)
	go process.drain(process.stderr, process.stderrSink)
	go process.wait()
}

func (process *nativeProcess) drain(source *os.File, destination io.Writer) {
	defer process.ioWait.Done()
	if _, err := io.Copy(destination, source); err != nil {
		process.markRuntimeFailure()
	}
	if err := source.Close(); err != nil {
		process.markRuntimeFailure()
	}
}

func (process *nativeProcess) wait() {
	event, waitErr := windows.WaitForSingleObject(process.process, windows.INFINITE)
	var exitCode uint32
	if waitErr != nil || event != windows.WAIT_OBJECT_0 {
		process.markRuntimeFailure()
	} else if err := windows.GetExitCodeProcess(process.process, &exitCode); err != nil {
		process.markRuntimeFailure()
	}

	reapContext, cancel := context.WithTimeout(context.Background(), nativeReapLimit)
	if err := process.job.terminateAndWait(reapContext); err != nil {
		process.markRuntimeFailure()
	}
	cancel()
	process.ioWait.Wait()
	if err := windows.CloseHandle(process.process); err != nil {
		process.markRuntimeFailure()
	}
	process.process = 0
	if err := process.job.close(); err != nil {
		process.markRuntimeFailure()
	}
	if err := process.lease.Close(); err != nil {
		process.markRuntimeFailure()
	}

	result := executionrun.ProcessExit{Code: int64(exitCode)}
	if process.hasRuntimeFailure() {
		result.Code = 0
		result.RuntimeError = boundaryError("process-runtime-failed")
	}
	process.exit <- result
	close(process.exit)
	close(process.done)
}

func (process *nativeProcess) Exit() <-chan executionrun.ProcessExit {
	return process.exit
}

func (process *nativeProcess) TerminateTree(ctx context.Context) error {
	if ctx == nil {
		return boundaryError("termination-context-required")
	}
	select {
	case <-process.done:
		return nil
	default:
	}
	if err := process.job.terminate(); err != nil {
		select {
		case <-process.done:
			return nil
		default:
			return err
		}
	}
	select {
	case <-process.done:
		return nil
	case <-ctx.Done():
		return boundaryError("termination-deadline")
	}
}

func (process *nativeProcess) markRuntimeFailure() {
	process.errorMu.Lock()
	process.runtimeFail = true
	process.errorMu.Unlock()
}

func (process *nativeProcess) hasRuntimeFailure() bool {
	process.errorMu.Lock()
	defer process.errorMu.Unlock()
	return process.runtimeFail
}
