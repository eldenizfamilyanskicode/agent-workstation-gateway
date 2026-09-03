package executionrun

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/artifactpattern"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionpolicy"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/outputcapture"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/shellinvoke"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

const defaultTreeTerminationGrace = 10 * time.Second
const defaultArtifactCollectionTimeout = 30 * time.Second

type Runner struct {
	launcher                  Launcher
	collector                 ArtifactCollector
	clock                     Clock
	timers                    TimerFactory
	treeTerminationGrace      time.Duration
	artifactCollectionTimeout time.Duration
	backgroundMu              sync.Mutex
	background                map[string]*backgroundProcess
}

func New(launcher Launcher, collector ArtifactCollector, options Options) (*Runner, error) {
	if launcher == nil {
		return nil, ErrLauncherRequired
	}
	if options.TreeTerminationGrace < 0 || options.ArtifactCollectionTimeout < 0 {
		return nil, ErrInvalidOptions
	}
	clock := options.Clock
	if clock == nil {
		clock = systemClock{}
	}
	timers := options.Timers
	if timers == nil {
		timers = systemTimerFactory{}
	}
	treeTerminationGrace := options.TreeTerminationGrace
	if treeTerminationGrace == 0 {
		treeTerminationGrace = defaultTreeTerminationGrace
	}
	artifactCollectionTimeout := options.ArtifactCollectionTimeout
	if artifactCollectionTimeout == 0 {
		artifactCollectionTimeout = defaultArtifactCollectionTimeout
	}
	return &Runner{
		launcher: launcher, collector: collector, clock: clock, timers: timers,
		treeTerminationGrace: treeTerminationGrace, artifactCollectionTimeout: artifactCollectionTimeout,
		background: make(map[string]*backgroundProcess),
	}, nil
}

func (runner *Runner) Run(ctx context.Context, plan executionpolicy.LaunchPlan, gatewaySourceSHA string) (Output, error) {
	switch plan.Operation {
	case v1.RequestOperationExecute:
		return runner.runForeground(ctx, plan, gatewaySourceSHA)
	case v1.RequestOperationStart, v1.RequestOperationStatus, v1.RequestOperationStop, v1.RequestOperationLogs:
		return runner.runBackground(ctx, plan, gatewaySourceSHA)
	default:
		return Output{}, ErrInvalidLaunchPlan
	}
}

func (runner *Runner) runForeground(ctx context.Context, plan executionpolicy.LaunchPlan, gatewaySourceSHA string) (Output, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if plan.TimeoutSeconds < v1.MinTimeoutSeconds || plan.TimeoutSeconds > v1.MaxTimeoutSeconds {
		return Output{}, ErrInvalidLaunchPlan
	}
	stdoutCapture, err := outputcapture.New(plan.MaxOutputBytes)
	if err != nil {
		return Output{}, ErrInvalidLaunchPlan
	}
	stderrCapture, err := outputcapture.New(plan.MaxOutputBytes)
	if err != nil {
		return Output{}, ErrInvalidLaunchPlan
	}
	invocation, err := shellinvoke.Build(plan)
	if err != nil {
		return Output{}, errors.Join(ErrInvalidLaunchPlan, err)
	}

	startedAt := runner.clock.Now().UTC()
	stdoutBefore, err := stdoutCapture.Snapshot()
	if err != nil {
		return Output{}, ErrInvalidExecutionReport
	}
	stderrBefore, err := stderrCapture.Snapshot()
	if err != nil {
		return Output{}, ErrInvalidExecutionReport
	}
	preflight := assembleReport(plan, gatewaySourceSHA, v1.CommandStatusRuntimeFailed, nil, startedAt, startedAt, stdoutBefore, stderrBefore, failedArtifactManifest(plan.Artifacts))
	if err := v1.ValidateExecutionReport(preflight); err != nil {
		return Output{}, errors.Join(ErrInvalidLaunchPlan, err)
	}

	nativeLaunch := NativeLaunch{
		ExecutionIdentity: plan.ExecutionIdentity,
		WorkingDirectory:  plan.WorkingDirectory,
		ApprovedRoot:      plan.ApprovedRoot,
		Environment:       append([]string(nil), plan.Environment...),
		Capabilities:      append([]installconfig.Capability(nil), plan.Capabilities...),
		Invocation:        invocation,
	}
	process, startErr := runner.launcher.Start(ctx, nativeLaunch, stdoutCapture, stderrCapture)
	status := v1.CommandStatusRuntimeFailed
	var exitCode *int64
	safeToCollect := false
	if startErr != nil && process != nil {
		_ = runner.terminateTree(process)
	} else if startErr == nil && process != nil {
		status, exitCode, safeToCollect = runner.awaitProcess(ctx, plan, process)
	}

	finishedAt := runner.clock.Now().UTC()
	if finishedAt.Before(startedAt) {
		return Output{}, ErrClockRegression
	}
	stdout, err := stdoutCapture.Snapshot()
	if err != nil {
		return Output{}, ErrInvalidExecutionReport
	}
	stderr, err := stderrCapture.Snapshot()
	if err != nil {
		return Output{}, ErrInvalidExecutionReport
	}

	artifacts := failedArtifactManifest(plan.Artifacts)
	var artifactBundle ArtifactBundle
	if safeToCollect {
		artifacts, artifactBundle = runner.collectArtifacts(plan)
	}
	report := assembleReport(plan, gatewaySourceSHA, status, exitCode, startedAt, finishedAt, stdout, stderr, artifacts)
	if err := v1.ValidateExecutionReport(report); err != nil {
		closeArtifactBundle(artifactBundle)
		artifactBundle = nil
		report.Artifacts = failedArtifactManifest(plan.Artifacts)
		if fallbackErr := v1.ValidateExecutionReport(report); fallbackErr != nil {
			return Output{}, errors.Join(ErrInvalidExecutionReport, fallbackErr)
		}
	}
	return Output{
		Report: report, Stdout: stdout.Retained, Stderr: stderr.Retained,
		ArtifactBundle: artifactBundle,
	}, nil
}

func (runner *Runner) awaitProcess(ctx context.Context, plan executionpolicy.LaunchPlan, process Process) (v1.CommandStatus, *int64, bool) {
	exitSignal := process.Exit()
	if exitSignal == nil {
		return v1.CommandStatusRuntimeFailed, nil, runner.terminateTree(process) == nil
	}
	timer := runner.timers.NewTimer(time.Duration(plan.TimeoutSeconds) * time.Second)
	if timer == nil {
		return v1.CommandStatusRuntimeFailed, nil, runner.terminateTree(process) == nil
	}
	defer timer.Stop()
	timerChannel := timer.Channel()
	if timerChannel == nil {
		return v1.CommandStatusRuntimeFailed, nil, runner.terminateTree(process) == nil
	}
	select {
	case processExit, open := <-exitSignal:
		if !open || processExit.RuntimeError != nil || processExit.Code < 0 || processExit.Code > 4294967295 {
			return v1.CommandStatusRuntimeFailed, nil, true
		}
		exitCode := processExit.Code
		if exitCode == 0 {
			return v1.CommandStatusCompleted, &exitCode, true
		}
		return v1.CommandStatusFailed, &exitCode, true
	case <-ctx.Done():
		if runner.terminateTree(process) != nil {
			return v1.CommandStatusRuntimeFailed, nil, false
		}
		return v1.CommandStatusCancelled, nil, true
	case <-timerChannel:
		status := v1.CommandStatusTimedOut
		if ctx.Err() != nil {
			status = v1.CommandStatusCancelled
		}
		if runner.terminateTree(process) != nil {
			return v1.CommandStatusRuntimeFailed, nil, false
		}
		return status, nil, true
	}
}

func (runner *Runner) terminateTree(process Process) error {
	terminationContext, cancel := context.WithTimeout(context.Background(), runner.treeTerminationGrace)
	defer cancel()
	return process.TerminateTree(terminationContext)
}

func assembleReport(
	plan executionpolicy.LaunchPlan,
	gatewaySourceSHA string,
	status v1.CommandStatus,
	exitCode *int64,
	startedAt time.Time,
	finishedAt time.Time,
	stdout outputcapture.Snapshot,
	stderr outputcapture.Snapshot,
	artifacts v1.ArtifactManifest,
) v1.ExecutionReport {
	return v1.ExecutionReport{
		ProtocolVersion: v1.Version, RequestID: plan.RequestID, RequestDigest: plan.RequestDigest,
		AttemptID: plan.AttemptID, GatewaySourceSHA: gatewaySourceSHA, CommandStatus: status, ExitCode: exitCode,
		StartedAt: startedAt.Format(time.RFC3339Nano), FinishedAt: finishedAt.Format(time.RFC3339Nano),
		DurationMilliseconds: finishedAt.Sub(startedAt).Milliseconds(), Stdout: stdout.Metadata, Stderr: stderr.Metadata,
		Artifacts: artifacts,
	}
}

func artifactCollectionAllowed(manifest v1.ArtifactManifest, selections []v1.ArtifactSelection) bool {
	groups := make(map[string]map[string]struct{}, len(selections))
	for _, selection := range selections {
		patterns := make(map[string]struct{}, len(selection.Paths))
		for _, pattern := range selection.Paths {
			patterns[pattern] = struct{}{}
		}
		groups[selection.Name] = patterns
	}
	if len(groups) == 0 {
		return manifest.Status == v1.ArtifactStatusNotRequested && len(manifest.Files) == 0 && len(manifest.Omissions) == 0
	}
	if manifest.Status == v1.ArtifactStatusNotRequested {
		return false
	}
	for _, file := range manifest.Files {
		patterns, ok := groups[file.Group]
		if !ok {
			return false
		}
		matched := false
		for pattern := range patterns {
			patternMatch, err := artifactpattern.Match(pattern, file.Path)
			if err != nil {
				return false
			}
			matched = matched || patternMatch
		}
		if !matched {
			return false
		}
	}
	for _, omission := range manifest.Omissions {
		patterns, ok := groups[omission.Group]
		if !ok {
			return false
		}
		if _, ok := patterns[omission.Pattern]; !ok {
			return false
		}
	}
	return true
}

func failedArtifactManifest(selections []v1.ArtifactSelection) v1.ArtifactManifest {
	if len(selections) == 0 {
		return v1.ArtifactManifest{Status: v1.ArtifactStatusNotRequested, Files: []v1.ArtifactFile{}, Omissions: []v1.ArtifactOmission{}}
	}
	omissions := make([]v1.ArtifactOmission, 0)
	for _, selection := range selections {
		for _, pattern := range selection.Paths {
			omissions = append(omissions, v1.ArtifactOmission{
				Group: selection.Name, Pattern: pattern, Reason: v1.ArtifactOmissionCollectionFailed,
			})
		}
	}
	return v1.ArtifactManifest{Status: v1.ArtifactStatusFailed, Files: []v1.ArtifactFile{}, Omissions: omissions}
}

func (runner *Runner) collectArtifacts(plan executionpolicy.LaunchPlan) (v1.ArtifactManifest, ArtifactBundle) {
	if len(plan.Artifacts) == 0 {
		return failedArtifactManifest(nil), nil
	}
	if runner.collector == nil {
		return failedArtifactManifest(plan.Artifacts), nil
	}
	collectionContext, cancel := context.WithTimeout(context.Background(), runner.artifactCollectionTimeout)
	defer cancel()
	collection, err := runner.collector.Collect(collectionContext, ArtifactPlan{
		ExecutionIdentity: plan.ExecutionIdentity,
		WorkingDirectory:  plan.WorkingDirectory,
		ApprovedRoot:      plan.ApprovedRoot,
		Selections:        cloneSelections(plan.Artifacts),
	})
	if err != nil || !artifactCollectionAllowed(collection.Manifest, plan.Artifacts) ||
		(len(collection.Manifest.Files) > 0 && collection.Bundle == nil) {
		closeArtifactBundle(collection.Bundle)
		return failedArtifactManifest(plan.Artifacts), nil
	}
	if len(collection.Manifest.Files) == 0 && collection.Bundle != nil {
		closeArtifactBundle(collection.Bundle)
		collection.Bundle = nil
	}
	return collection.Manifest, collection.Bundle
}

func closeArtifactBundle(bundle ArtifactBundle) {
	if bundle != nil {
		_ = bundle.Close()
	}
}

func cloneSelections(selections []v1.ArtifactSelection) []v1.ArtifactSelection {
	cloned := make([]v1.ArtifactSelection, len(selections))
	for index, selection := range selections {
		cloned[index] = v1.ArtifactSelection{Name: selection.Name, Paths: append([]string(nil), selection.Paths...)}
	}
	return cloned
}
