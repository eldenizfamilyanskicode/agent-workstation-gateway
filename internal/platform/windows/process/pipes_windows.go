//go:build windows

package process

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

type processPipes struct {
	stdinChild   windows.Handle
	stdinParent  windows.Handle
	stdoutChild  windows.Handle
	stdoutParent windows.Handle
	stderrChild  windows.Handle
	stderrParent windows.Handle
}

func newProcessPipes() (*processPipes, error) {
	pipes := &processPipes{}
	attributes := windows.SecurityAttributes{
		Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1,
	}
	if err := windows.CreatePipe(&pipes.stdinChild, &pipes.stdinParent, &attributes, 0); err != nil {
		return nil, boundaryError("stdin-pipe-create-failed")
	}
	if err := windows.SetHandleInformation(pipes.stdinParent, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		pipes.closeAll()
		return nil, boundaryError("stdin-pipe-policy-failed")
	}
	if err := windows.CreatePipe(&pipes.stdoutParent, &pipes.stdoutChild, &attributes, 0); err != nil {
		pipes.closeAll()
		return nil, boundaryError("stdout-pipe-create-failed")
	}
	if err := windows.SetHandleInformation(pipes.stdoutParent, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		pipes.closeAll()
		return nil, boundaryError("stdout-pipe-policy-failed")
	}
	if err := windows.CreatePipe(&pipes.stderrParent, &pipes.stderrChild, &attributes, 0); err != nil {
		pipes.closeAll()
		return nil, boundaryError("stderr-pipe-create-failed")
	}
	if err := windows.SetHandleInformation(pipes.stderrParent, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		pipes.closeAll()
		return nil, boundaryError("stderr-pipe-policy-failed")
	}
	return pipes, nil
}

func (pipes *processPipes) childHandles() []windows.Handle {
	return []windows.Handle{pipes.stdinChild, pipes.stdoutChild, pipes.stderrChild}
}

func (pipes *processPipes) closeChildEnds() {
	closeHandle(&pipes.stdinChild)
	closeHandle(&pipes.stdoutChild)
	closeHandle(&pipes.stderrChild)
}

func (pipes *processPipes) parentFiles() (*os.File, *os.File, *os.File, error) {
	stdin := takeFile(&pipes.stdinParent, "awg-stdin")
	stdout := takeFile(&pipes.stdoutParent, "awg-stdout")
	stderr := takeFile(&pipes.stderrParent, "awg-stderr")
	if stdin == nil || stdout == nil || stderr == nil {
		if stdin != nil {
			stdin.Close()
		}
		if stdout != nil {
			stdout.Close()
		}
		if stderr != nil {
			stderr.Close()
		}
		return nil, nil, nil, boundaryError("pipe-file-conversion-failed")
	}
	return stdin, stdout, stderr, nil
}

func (pipes *processPipes) closeAll() {
	closeHandle(&pipes.stdinChild)
	closeHandle(&pipes.stdinParent)
	closeHandle(&pipes.stdoutChild)
	closeHandle(&pipes.stdoutParent)
	closeHandle(&pipes.stderrChild)
	closeHandle(&pipes.stderrParent)
}

func takeFile(handle *windows.Handle, name string) *os.File {
	if *handle == 0 || *handle == windows.InvalidHandle {
		return nil
	}
	file := os.NewFile(uintptr(*handle), name)
	*handle = 0
	return file
}

func closeHandle(handle *windows.Handle) {
	if *handle != 0 && *handle != windows.InvalidHandle {
		_ = windows.CloseHandle(*handle)
	}
	*handle = 0
}
