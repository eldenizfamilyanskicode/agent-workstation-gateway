//go:build windows

package process

import (
	"context"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const terminatedExitCode uint32 = 0xC000013A

type jobObject struct {
	handle windows.Handle
	mu     sync.Mutex
}

type jobAccounting struct {
	TotalUserTime             int64
	TotalKernelTime           int64
	ThisPeriodTotalUserTime   int64
	ThisPeriodTotalKernelTime int64
	TotalPageFaultCount       uint32
	TotalProcesses            uint32
	ActiveProcesses           uint32
	TotalTerminatedProcesses  uint32
}

func newJobObject() (*jobObject, error) {
	handle, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, boundaryError("job-create-failed")
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(
		handle,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)),
		uint32(unsafe.Sizeof(limits)),
	); err != nil {
		windows.CloseHandle(handle)
		return nil, boundaryError("job-policy-failed")
	}
	return &jobObject{handle: handle}, nil
}

func (job *jobObject) assign(process windows.Handle) error {
	job.mu.Lock()
	defer job.mu.Unlock()
	if job.handle == 0 {
		return boundaryError("job-closed")
	}
	if err := windows.AssignProcessToJobObject(job.handle, process); err != nil {
		return boundaryError("job-assignment-failed")
	}
	return nil
}

func (job *jobObject) terminate() error {
	job.mu.Lock()
	defer job.mu.Unlock()
	if job.handle == 0 {
		return boundaryError("job-closed")
	}
	if err := windows.TerminateJobObject(job.handle, terminatedExitCode); err != nil {
		return boundaryError("job-termination-failed")
	}
	return nil
}

func (job *jobObject) activeProcesses() (uint32, error) {
	job.mu.Lock()
	defer job.mu.Unlock()
	if job.handle == 0 {
		return 0, boundaryError("job-closed")
	}
	accounting := jobAccounting{}
	if err := windows.QueryInformationJobObject(
		job.handle,
		windows.JobObjectBasicAccountingInformation,
		uintptr(unsafe.Pointer(&accounting)),
		uint32(unsafe.Sizeof(accounting)),
		nil,
	); err != nil {
		return 0, boundaryError("job-query-failed")
	}
	return accounting.ActiveProcesses, nil
}

func (job *jobObject) terminateAndWait(ctx context.Context) error {
	active, err := job.activeProcesses()
	if err != nil {
		return err
	}
	if active != 0 {
		if err := job.terminate(); err != nil {
			return err
		}
	}
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		active, err = job.activeProcesses()
		if err != nil {
			return err
		}
		if active == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return boundaryError("job-reap-deadline")
		case <-ticker.C:
		}
	}
}

func (job *jobObject) close() error {
	if job == nil {
		return nil
	}
	job.mu.Lock()
	defer job.mu.Unlock()
	if job.handle == 0 {
		return nil
	}
	err := windows.CloseHandle(job.handle)
	job.handle = 0
	return err
}
