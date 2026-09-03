package executionrun

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionpolicy"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/outputcapture"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/shellinvoke"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

const maxBackgroundProcesses = 32

const (
	backgroundRunning       = "running"
	backgroundExited        = "exited"
	backgroundStopped       = "stopped"
	backgroundTimedOut      = "timed_out"
	backgroundRuntimeFailed = "runtime_failed"
)

type backgroundProcess struct {
	process          Process
	workingDirectory string
	startedAt        time.Time
	stdout           *outputcapture.Capture
	stderr           *outputcapture.Capture
	done             chan struct{}
	finishOnce       sync.Once

	mu         sync.Mutex
	state      string
	reason     string
	finishedAt time.Time
	exitCode   *int64
}

type backgroundHeader struct {
	ProcessID  string            `json:"process_id"`
	State      string            `json:"state"`
	StartedAt  string            `json:"started_at"`
	FinishedAt string            `json:"finished_at"`
	ExitCode   *int64            `json:"exit_code"`
	Stdout     v1.OutputMetadata `json:"stdout"`
	Stderr     v1.OutputMetadata `json:"stderr"`
}

func (runner *Runner) runBackground(ctx context.Context, plan executionpolicy.LaunchPlan, gatewaySourceSHA string) (Output, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateBackgroundPlan(plan, gatewaySourceSHA); err != nil {
		return Output{}, err
	}
	startedAt := runner.clock.Now().UTC()
	var stdout []byte
	var stderr []byte
	status := v1.CommandStatusCompleted
	exitCode := int64(0)

	switch plan.Operation {
	case v1.RequestOperationStart:
		entry, err := runner.startBackground(ctx, plan)
		if err != nil {
			status, exitCode, stderr = backgroundOperationFailure(err)
		} else {
			stdout, stderr, err = backgroundResponse(plan, entry, false)
			if err != nil {
				status, exitCode, stderr = backgroundOperationFailure(err)
			}
		}
	case v1.RequestOperationStatus, v1.RequestOperationLogs:
		entry, err := runner.findBackground(plan)
		if err != nil {
			status, exitCode, stderr = backgroundOperationFailure(err)
		} else {
			stdout, stderr, err = backgroundResponse(plan, entry, plan.Operation == v1.RequestOperationLogs)
			if err != nil {
				status, exitCode, stderr = backgroundOperationFailure(err)
			}
		}
	case v1.RequestOperationStop:
		entry, err := runner.stopBackground(ctx, plan)
		if err != nil {
			status = v1.CommandStatusRuntimeFailed
			exitCode = 0
			stderr = []byte("background process stop failed\n")
		} else {
			stdout, stderr, err = backgroundResponse(plan, entry, false)
			if err != nil {
				status, exitCode, stderr = backgroundOperationFailure(err)
			}
		}
	}

	finishedAt := runner.clock.Now().UTC()
	if finishedAt.Before(startedAt) {
		return Output{}, ErrClockRegression
	}
	var reportExit *int64
	if status != v1.CommandStatusRuntimeFailed {
		reportExit = &exitCode
	}
	return buildBackgroundOutput(plan, gatewaySourceSHA, status, reportExit, startedAt, finishedAt, stdout, stderr)
}

func validateBackgroundPlan(plan executionpolicy.LaunchPlan, gatewaySourceSHA string) error {
	if plan.Operation != v1.RequestOperationStart && plan.Operation != v1.RequestOperationStatus &&
		plan.Operation != v1.RequestOperationStop && plan.Operation != v1.RequestOperationLogs {
		return ErrInvalidLaunchPlan
	}
	if plan.ProcessID == "" || plan.TimeoutSeconds < v1.MinTimeoutSeconds || plan.TimeoutSeconds > v1.MaxTimeoutSeconds ||
		plan.MaxOutputBytes < v1.MinOutputBytes || plan.MaxOutputBytes > v1.MaxOutputBytes || len(plan.Artifacts) != 0 {
		return ErrInvalidLaunchPlan
	}
	if _, err := shellinvoke.Build(plan); err != nil {
		return errors.Join(ErrInvalidLaunchPlan, err)
	}
	empty, err := outputcapture.New(plan.MaxOutputBytes)
	if err != nil {
		return ErrInvalidLaunchPlan
	}
	snapshot, err := empty.Snapshot()
	if err != nil {
		return ErrInvalidLaunchPlan
	}
	now := time.Unix(0, 0).UTC()
	report := assembleReport(
		plan, gatewaySourceSHA, v1.CommandStatusRuntimeFailed, nil, now, now,
		snapshot, snapshot, failedArtifactManifest(nil),
	)
	if err := v1.ValidateExecutionReport(report); err != nil {
		return errors.Join(ErrInvalidLaunchPlan, err)
	}
	return nil
}

func (runner *Runner) startBackground(ctx context.Context, plan executionpolicy.LaunchPlan) (*backgroundProcess, error) {
	key := backgroundKey(plan.SessionID, plan.ProcessID)
	runner.backgroundMu.Lock()
	if _, exists := runner.background[key]; exists {
		runner.backgroundMu.Unlock()
		return nil, errors.New("background process already exists")
	}
	if len(runner.background) >= maxBackgroundProcesses {
		runner.backgroundMu.Unlock()
		return nil, errors.New("background process capacity reached")
	}
	stdout, stdoutErr := outputcapture.New(plan.MaxOutputBytes)
	stderr, stderrErr := outputcapture.New(plan.MaxOutputBytes)
	if stdoutErr != nil || stderrErr != nil {
		runner.backgroundMu.Unlock()
		return nil, ErrInvalidLaunchPlan
	}
	entry := &backgroundProcess{
		workingDirectory: plan.WorkingDirectory,
		startedAt:        runner.clock.Now().UTC(),
		stdout:           stdout,
		stderr:           stderr,
		done:             make(chan struct{}),
		state:            backgroundRunning,
	}
	invocation, err := shellinvoke.Build(plan)
	if err != nil {
		runner.backgroundMu.Unlock()
		return nil, err
	}
	nativeLaunch := NativeLaunch{
		ExecutionIdentity: plan.ExecutionIdentity,
		WorkingDirectory:  plan.WorkingDirectory,
		ApprovedRoot:      plan.ApprovedRoot,
		Environment:       append([]string(nil), plan.Environment...),
		Capabilities:      append([]installconfig.Capability(nil), plan.Capabilities...),
		Invocation:        invocation,
	}
	process, err := runner.launcher.Start(ctx, nativeLaunch, stdout, stderr)
	if err != nil || process == nil {
		if process != nil {
			_ = runner.terminateTree(process)
		}
		runner.backgroundMu.Unlock()
		return nil, errors.New("background process launch failed")
	}
	entry.process = process
	runner.background[key] = entry
	runner.backgroundMu.Unlock()
	go runner.monitorBackground(entry, time.Duration(plan.TimeoutSeconds)*time.Second)
	return entry, nil
}

func (runner *Runner) monitorBackground(entry *backgroundProcess, lifetime time.Duration) {
	if entry.process == nil || entry.process.Exit() == nil {
		entry.finish(backgroundRuntimeFailed, nil, runner.clock.Now().UTC())
		return
	}
	timer := runner.timers.NewTimer(lifetime)
	if timer == nil || timer.Channel() == nil {
		_ = runner.terminateTree(entry.process)
		entry.finish(backgroundRuntimeFailed, nil, runner.clock.Now().UTC())
		return
	}
	defer timer.Stop()
	select {
	case processExit, open := <-entry.process.Exit():
		state := entry.reasonOr(backgroundExited)
		if !open || processExit.RuntimeError != nil || processExit.Code < 0 || processExit.Code > 4294967295 {
			entry.finish(backgroundRuntimeFailed, nil, runner.clock.Now().UTC())
			return
		}
		exitCode := processExit.Code
		entry.finish(state, &exitCode, runner.clock.Now().UTC())
	case <-timer.Channel():
		reason := entry.setReason(backgroundTimedOut)
		if reason == backgroundTimedOut {
			if err := runner.terminateTree(entry.process); err != nil {
				entry.finish(backgroundRuntimeFailed, nil, runner.clock.Now().UTC())
				return
			}
			entry.finish(backgroundTimedOut, nil, runner.clock.Now().UTC())
			return
		}
		processExit, open := <-entry.process.Exit()
		if !open || processExit.RuntimeError != nil || processExit.Code < 0 || processExit.Code > 4294967295 {
			entry.finish(backgroundRuntimeFailed, nil, runner.clock.Now().UTC())
			return
		}
		exitCode := processExit.Code
		entry.finish(reason, &exitCode, runner.clock.Now().UTC())
	}
}

func (runner *Runner) findBackground(plan executionpolicy.LaunchPlan) (*backgroundProcess, error) {
	key := backgroundKey(plan.SessionID, plan.ProcessID)
	runner.backgroundMu.Lock()
	entry := runner.background[key]
	runner.backgroundMu.Unlock()
	if entry == nil || entry.workingDirectory != plan.WorkingDirectory {
		return nil, errors.New("background process not found")
	}
	return entry, nil
}

func (runner *Runner) stopBackground(ctx context.Context, plan executionpolicy.LaunchPlan) (*backgroundProcess, error) {
	entry, err := runner.findBackground(plan)
	if err != nil {
		return nil, err
	}
	if entry.running() {
		entry.setReason(backgroundStopped)
		if err := runner.terminateTree(entry.process); err != nil {
			return nil, err
		}
		select {
		case <-entry.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	runner.removeBackground(backgroundKey(plan.SessionID, plan.ProcessID), entry)
	return entry, nil
}

func (runner *Runner) Close(ctx context.Context) error {
	if runner == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runner.backgroundMu.Lock()
	entries := make([]*backgroundProcess, 0, len(runner.background))
	for _, entry := range runner.background {
		entries = append(entries, entry)
	}
	runner.backgroundMu.Unlock()
	var result error
	for _, entry := range entries {
		if !entry.running() {
			continue
		}
		entry.setReason(backgroundStopped)
		if err := entry.process.TerminateTree(ctx); err != nil {
			result = errors.Join(result, err)
			continue
		}
		select {
		case <-entry.done:
		case <-ctx.Done():
			result = errors.Join(result, ctx.Err())
		}
	}
	return result
}

func backgroundResponse(plan executionpolicy.LaunchPlan, entry *backgroundProcess, includeLogs bool) ([]byte, []byte, error) {
	stdout, err := entry.stdout.Snapshot()
	if err != nil {
		return nil, nil, err
	}
	stderr, err := entry.stderr.Snapshot()
	if err != nil {
		return nil, nil, err
	}
	state, finishedAt, exitCode := entry.snapshotState()
	header := backgroundHeader{
		ProcessID: plan.ProcessID, State: state, StartedAt: entry.startedAt.Format(time.RFC3339Nano),
		FinishedAt: finishedAt, ExitCode: exitCode, Stdout: stdout.Metadata, Stderr: stderr.Metadata,
	}
	encoded, err := json.Marshal(header)
	if err != nil {
		return nil, nil, err
	}
	encoded = append(encoded, '\n')
	if !includeLogs {
		return encoded, nil, nil
	}
	return append(encoded, stdout.Retained...), stderr.Retained, nil
}

func buildBackgroundOutput(
	plan executionpolicy.LaunchPlan,
	gatewaySourceSHA string,
	status v1.CommandStatus,
	exitCode *int64,
	startedAt time.Time,
	finishedAt time.Time,
	stdoutBytes []byte,
	stderrBytes []byte,
) (Output, error) {
	stdoutCapture, err := outputcapture.New(plan.MaxOutputBytes)
	if err != nil {
		return Output{}, ErrInvalidLaunchPlan
	}
	stderrCapture, err := outputcapture.New(plan.MaxOutputBytes)
	if err != nil {
		return Output{}, ErrInvalidLaunchPlan
	}
	if _, err := io.Copy(stdoutCapture, bytes.NewReader(stdoutBytes)); err != nil {
		return Output{}, ErrInvalidExecutionReport
	}
	if _, err := io.Copy(stderrCapture, bytes.NewReader(stderrBytes)); err != nil {
		return Output{}, ErrInvalidExecutionReport
	}
	stdout, err := stdoutCapture.Snapshot()
	if err != nil {
		return Output{}, ErrInvalidExecutionReport
	}
	stderr, err := stderrCapture.Snapshot()
	if err != nil {
		return Output{}, ErrInvalidExecutionReport
	}
	report := assembleReport(plan, gatewaySourceSHA, status, exitCode, startedAt, finishedAt, stdout, stderr, failedArtifactManifest(nil))
	if err := v1.ValidateExecutionReport(report); err != nil {
		return Output{}, errors.Join(ErrInvalidExecutionReport, err)
	}
	return Output{Report: report, Stdout: stdout.Retained, Stderr: stderr.Retained}, nil
}

func backgroundOperationFailure(_ error) (v1.CommandStatus, int64, []byte) {
	return v1.CommandStatusFailed, 1, []byte("background process operation denied\n")
}

func backgroundKey(sessionID string, processID string) string { return sessionID + "\x00" + processID }

func (runner *Runner) removeBackground(key string, expected *backgroundProcess) {
	runner.backgroundMu.Lock()
	if runner.background[key] == expected {
		delete(runner.background, key)
	}
	runner.backgroundMu.Unlock()
}

func (entry *backgroundProcess) running() bool {
	entry.mu.Lock()
	defer entry.mu.Unlock()
	return entry.state == backgroundRunning
}

func (entry *backgroundProcess) setReason(reason string) string {
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.reason == "" {
		entry.reason = reason
	}
	return entry.reason
}

func (entry *backgroundProcess) reasonOr(fallback string) string {
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.reason != "" {
		return entry.reason
	}
	return fallback
}

func (entry *backgroundProcess) finish(state string, exitCode *int64, finishedAt time.Time) {
	entry.finishOnce.Do(func() {
		entry.mu.Lock()
		entry.state = state
		entry.finishedAt = finishedAt
		if exitCode != nil {
			value := *exitCode
			entry.exitCode = &value
		}
		entry.mu.Unlock()
		close(entry.done)
	})
}

func (entry *backgroundProcess) snapshotState() (string, string, *int64) {
	entry.mu.Lock()
	defer entry.mu.Unlock()
	finishedAt := ""
	if !entry.finishedAt.IsZero() {
		finishedAt = entry.finishedAt.Format(time.RFC3339Nano)
	}
	var exitCode *int64
	if entry.exitCode != nil {
		value := *entry.exitCode
		exitCode = &value
	}
	return entry.state, finishedAt, exitCode
}
