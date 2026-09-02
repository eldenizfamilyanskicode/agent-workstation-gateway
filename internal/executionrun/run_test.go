package executionrun

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionpolicy"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

type fakeLauncher struct {
	process Process
	err     error
	stdout  []byte
	stderr  []byte
	launch  NativeLaunch
	calls   int
}

func (launcher *fakeLauncher) Start(_ context.Context, launch NativeLaunch, stdout io.Writer, stderr io.Writer) (Process, error) {
	launcher.calls++
	launcher.launch = launch
	if len(launcher.stdout) > 0 {
		_, _ = stdout.Write(launcher.stdout)
	}
	if len(launcher.stderr) > 0 {
		_, _ = stderr.Write(launcher.stderr)
	}
	return launcher.process, launcher.err
}

type fakeProcess struct {
	exit           chan ProcessExit
	terminateErr   error
	mu             sync.Mutex
	terminateCalls int
}

func (process *fakeProcess) Exit() <-chan ProcessExit {
	return process.exit
}

func (process *fakeProcess) TerminateTree(_ context.Context) error {
	process.mu.Lock()
	defer process.mu.Unlock()
	process.terminateCalls++
	return process.terminateErr
}

func (process *fakeProcess) terminations() int {
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.terminateCalls
}

type fakeCollector struct {
	manifest v1.ArtifactManifest
	bundle   ArtifactBundle
	err      error
	plan     ArtifactPlan
	calls    int
}

func (collector *fakeCollector) Collect(_ context.Context, plan ArtifactPlan) (ArtifactCollection, error) {
	collector.calls++
	collector.plan = plan
	return ArtifactCollection{Manifest: collector.manifest, Bundle: collector.bundle}, collector.err
}

type fakeArtifactBundle struct {
	mu     sync.Mutex
	closed bool
}

func (*fakeArtifactBundle) Open(string, string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("synthetic artifact")), nil
}

func (bundle *fakeArtifactBundle) Close() error {
	bundle.mu.Lock()
	defer bundle.mu.Unlock()
	bundle.closed = true
	return nil
}

func (bundle *fakeArtifactBundle) isClosed() bool {
	bundle.mu.Lock()
	defer bundle.mu.Unlock()
	return bundle.closed
}

type sequenceClock struct {
	mu     sync.Mutex
	values []time.Time
	index  int
}

func (clock *sequenceClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	if clock.index >= len(clock.values) {
		return clock.values[len(clock.values)-1]
	}
	value := clock.values[clock.index]
	clock.index++
	return value
}

type fakeTimerFactory struct {
	fire     bool
	duration time.Duration
}

func (factory *fakeTimerFactory) NewTimer(duration time.Duration) Timer {
	factory.duration = duration
	channel := make(chan time.Time, 1)
	if factory.fire {
		channel <- time.Unix(0, 0)
	}
	return &fakeTimer{channel: channel}
}

type fakeTimer struct {
	channel chan time.Time
}

func (timer *fakeTimer) Channel() <-chan time.Time { return timer.channel }
func (timer *fakeTimer) Stop() bool                { return true }

func TestRunCompletesWithBoundedOutputAndIndependentArtifacts(t *testing.T) {
	plan := validLaunchPlan()
	marker := plan.Script
	stdout := []byte(strings.Repeat("o", plan.MaxOutputBytes+73))
	stderr := []byte("warning\n")
	process := processWithExit(ProcessExit{Code: 0})
	launcher := &fakeLauncher{process: process, stdout: stdout, stderr: stderr}
	bundle := &fakeArtifactBundle{}
	collector := &fakeCollector{manifest: completeArtifactManifest(), bundle: bundle}
	timers := &fakeTimerFactory{}
	runner := mustRunner(t, launcher, collector, timers)

	output, err := runner.Run(context.Background(), plan, strings.Repeat("c", 40))
	if err != nil {
		t.Fatal(err)
	}
	if err := v1.ValidateExecutionReport(output.Report); err != nil {
		t.Fatalf("runner produced invalid report: %v", err)
	}
	if output.Report.CommandStatus != v1.CommandStatusCompleted || output.Report.ExitCode == nil || *output.Report.ExitCode != 0 {
		t.Fatalf("unexpected command outcome: %#v", output.Report)
	}
	if output.Report.Stdout.TotalBytes != int64(len(stdout)) || output.Report.Stdout.RetainedBytes != int64(plan.MaxOutputBytes) || !output.Report.Stdout.Truncated {
		t.Fatalf("unexpected stdout metadata: %#v", output.Report.Stdout)
	}
	if len(output.Stdout) != plan.MaxOutputBytes || string(output.Stderr) != string(stderr) {
		t.Fatalf("unexpected retained output lengths: %d / %d", len(output.Stdout), len(output.Stderr))
	}
	if output.Report.Artifacts.Status != v1.ArtifactStatusComplete || collector.calls != 1 {
		t.Fatalf("artifact outcome was not independent: %#v", output.Report.Artifacts)
	}
	if output.ArtifactBundle != bundle {
		t.Fatal("runner dropped valid artifact content bundle")
	}
	if err := output.Close(); err != nil || !bundle.isClosed() {
		t.Fatalf("output did not close artifact bundle: %v", err)
	}
	if timers.duration != time.Second {
		t.Fatalf("unexpected command timer duration: %v", timers.duration)
	}
	trusted := append([]string{launcher.launch.Invocation.Executable()}, launcher.launch.Invocation.Arguments()...)
	for _, value := range trusted {
		if strings.Contains(value, marker) {
			t.Fatal("request script reached the trusted command vector")
		}
	}
	script, err := io.ReadAll(launcher.launch.Invocation.ScriptReader())
	if err != nil || string(script) != marker {
		t.Fatalf("script stdin changed: %q / %v", script, err)
	}
	if len(collector.plan.Selections) != 1 || collector.plan.WorkingDirectory != plan.WorkingDirectory || collector.plan.ApprovedRoot != plan.ApprovedRoot || collector.plan.ExecutionIdentity != plan.ExecutionIdentity {
		t.Fatalf("collector did not receive the restricted plan: %#v", collector.plan)
	}
}

func TestRunDistinguishesProcessOutcomes(t *testing.T) {
	runtimeFailure := errors.New("synthetic runtime failure")
	tests := []struct {
		name     string
		exit     ProcessExit
		closed   bool
		status   v1.CommandStatus
		exitCode *int64
	}{
		{name: "failed", exit: ProcessExit{Code: 17}, status: v1.CommandStatusFailed, exitCode: int64Ptr(17)},
		{name: "runtime error", exit: ProcessExit{RuntimeError: runtimeFailure}, status: v1.CommandStatusRuntimeFailed},
		{name: "invalid negative exit", exit: ProcessExit{Code: -1}, status: v1.CommandStatusRuntimeFailed},
		{name: "closed without result", closed: true, status: v1.CommandStatusRuntimeFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			process := &fakeProcess{exit: make(chan ProcessExit, 1)}
			if !test.closed {
				process.exit <- test.exit
			}
			close(process.exit)
			launcher := &fakeLauncher{process: process}
			collector := &fakeCollector{manifest: completeArtifactManifest(), bundle: &fakeArtifactBundle{}}
			runner := mustRunner(t, launcher, collector, &fakeTimerFactory{})
			output, err := runner.Run(context.Background(), validLaunchPlan(), strings.Repeat("c", 40))
			if err != nil {
				t.Fatal(err)
			}
			if output.Report.CommandStatus != test.status || !equalExitCode(output.Report.ExitCode, test.exitCode) {
				t.Fatalf("unexpected outcome: %s / %#v", output.Report.CommandStatus, output.Report.ExitCode)
			}
			if collector.calls != 1 {
				t.Fatal("a reaped command outcome skipped independent artifact collection")
			}
		})
	}
}

func TestRunTerminatesTreeOnTimeoutAndCancellation(t *testing.T) {
	tests := []struct {
		name   string
		cancel bool
		fire   bool
		status v1.CommandStatus
	}{
		{name: "timeout", fire: true, status: v1.CommandStatusTimedOut},
		{name: "cancellation", cancel: true, status: v1.CommandStatusCancelled},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			process := &fakeProcess{exit: make(chan ProcessExit)}
			launcher := &fakeLauncher{process: process}
			timers := &fakeTimerFactory{fire: test.fire}
			runner := mustRunner(t, launcher, nil, timers)
			ctx := context.Background()
			if test.cancel {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			plan := validLaunchPlan()
			plan.Artifacts = []v1.ArtifactSelection{}
			output, err := runner.Run(ctx, plan, strings.Repeat("c", 40))
			if err != nil {
				t.Fatal(err)
			}
			if output.Report.CommandStatus != test.status || output.Report.ExitCode != nil || process.terminations() != 1 {
				t.Fatalf("unexpected terminated outcome: %s / %d", output.Report.CommandStatus, process.terminations())
			}
		})
	}
}

func TestRunFailsClosedWhenTreeTerminationFails(t *testing.T) {
	process := &fakeProcess{exit: make(chan ProcessExit), terminateErr: errors.New("synthetic tree failure")}
	collector := &fakeCollector{manifest: completeArtifactManifest(), bundle: &fakeArtifactBundle{}}
	runner := mustRunner(t, &fakeLauncher{process: process}, collector, &fakeTimerFactory{fire: true})
	output, err := runner.Run(context.Background(), validLaunchPlan(), strings.Repeat("c", 40))
	if err != nil {
		t.Fatal(err)
	}
	if output.Report.CommandStatus != v1.CommandStatusRuntimeFailed || process.terminations() != 1 || collector.calls != 0 {
		t.Fatalf("tree failure did not fail closed: %s / %d / %d", output.Report.CommandStatus, process.terminations(), collector.calls)
	}
}

func TestRunReportsLaunchFailureAndCleansPartialProcess(t *testing.T) {
	process := &fakeProcess{exit: make(chan ProcessExit)}
	collector := &fakeCollector{manifest: completeArtifactManifest(), bundle: &fakeArtifactBundle{}}
	launcher := &fakeLauncher{process: process, err: errors.New("synthetic launch failure")}
	runner := mustRunner(t, launcher, collector, &fakeTimerFactory{})
	output, err := runner.Run(context.Background(), validLaunchPlan(), strings.Repeat("c", 40))
	if err != nil {
		t.Fatal(err)
	}
	if output.Report.CommandStatus != v1.CommandStatusRuntimeFailed || output.Report.ExitCode != nil {
		t.Fatalf("launch failure was misreported: %#v", output.Report)
	}
	if process.terminations() != 1 || collector.calls != 0 || output.Report.Artifacts.Status != v1.ArtifactStatusFailed {
		t.Fatalf("partial launch cleanup was unsafe: %d / %d / %s", process.terminations(), collector.calls, output.Report.Artifacts.Status)
	}
}

func TestRunPreservesCommandOutcomeWhenArtifactsFail(t *testing.T) {
	bundle := &fakeArtifactBundle{}
	collector := &fakeCollector{bundle: bundle, err: errors.New("synthetic collection failure")}
	runner := mustRunner(t, &fakeLauncher{process: processWithExit(ProcessExit{Code: 0})}, collector, &fakeTimerFactory{})
	output, err := runner.Run(context.Background(), validLaunchPlan(), strings.Repeat("c", 40))
	if err != nil {
		t.Fatal(err)
	}
	if output.Report.CommandStatus != v1.CommandStatusCompleted || output.Report.Artifacts.Status != v1.ArtifactStatusFailed {
		t.Fatalf("artifact failure overwrote command outcome: %s / %s", output.Report.CommandStatus, output.Report.Artifacts.Status)
	}
	if len(output.Report.Artifacts.Omissions) != 1 || output.Report.Artifacts.Omissions[0].Reason != v1.ArtifactOmissionCollectionFailed {
		t.Fatalf("artifact failure was not explicit: %#v", output.Report.Artifacts)
	}
	if output.ArtifactBundle != nil || !bundle.isClosed() {
		t.Fatal("failed collection retained content bundle")
	}
}

func TestRunRejectsUnboundArtifactContentAndClosesBundle(t *testing.T) {
	tests := []struct {
		name     string
		manifest v1.ArtifactManifest
		bundle   ArtifactBundle
	}{
		{name: "files require bundle", manifest: completeArtifactManifest()},
		{
			name: "file must match selection",
			manifest: v1.ArtifactManifest{
				Status: v1.ArtifactStatusComplete,
				Files: []v1.ArtifactFile{{
					Group: "results", Path: "unselected.txt", SHA256: strings.Repeat("d", 64), SizeBytes: 17,
				}},
				Omissions: []v1.ArtifactOmission{},
			},
			bundle: &fakeArtifactBundle{},
		},
		{
			name: "omission must name selection",
			manifest: v1.ArtifactManifest{
				Status: v1.ArtifactStatusFailed,
				Files:  []v1.ArtifactFile{},
				Omissions: []v1.ArtifactOmission{{
					Group: "results", Pattern: "other/*.json", Reason: v1.ArtifactOmissionNoMatch,
				}},
			},
			bundle: &fakeArtifactBundle{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			collector := &fakeCollector{manifest: test.manifest, bundle: test.bundle}
			runner := mustRunner(t, &fakeLauncher{process: processWithExit(ProcessExit{Code: 0})}, collector, &fakeTimerFactory{})
			output, err := runner.Run(context.Background(), validLaunchPlan(), strings.Repeat("c", 40))
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if output.Report.Artifacts.Status != v1.ArtifactStatusFailed || output.ArtifactBundle != nil {
				t.Fatalf("unbound artifact collection admitted: %#v", output)
			}
			if bundle, ok := test.bundle.(*fakeArtifactBundle); ok && !bundle.isClosed() {
				t.Fatal("rejected artifact bundle was not closed")
			}
		})
	}
}

func TestRunRejectsInvalidPlanBeforeNativeLaunch(t *testing.T) {
	launcher := &fakeLauncher{}
	runner := mustRunner(t, launcher, nil, &fakeTimerFactory{})
	plan := validLaunchPlan()
	plan.RequestDigest = "not-a-digest"
	if _, err := runner.Run(context.Background(), plan, strings.Repeat("c", 40)); !errors.Is(err, ErrInvalidLaunchPlan) {
		t.Fatalf("expected invalid plan error, got %v", err)
	}
	if launcher.calls != 0 {
		t.Fatal("invalid plan reached native launcher")
	}
}

func TestNewRequiresLauncherAndValidDurations(t *testing.T) {
	if _, err := New(nil, nil, Options{}); !errors.Is(err, ErrLauncherRequired) {
		t.Fatalf("expected launcher requirement, got %v", err)
	}
	if _, err := New(&fakeLauncher{}, nil, Options{TreeTerminationGrace: -time.Second}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("expected invalid options, got %v", err)
	}
}

func mustRunner(t *testing.T, launcher Launcher, collector ArtifactCollector, timers TimerFactory) *Runner {
	t.Helper()
	start := time.Date(2026, 9, 2, 18, 0, 1, 0, time.UTC)
	runner, err := New(launcher, collector, Options{
		Clock:  &sequenceClock{values: []time.Time{start, start.Add(250 * time.Millisecond)}},
		Timers: timers, TreeTerminationGrace: time.Second, ArtifactCollectionTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return runner
}

func validLaunchPlan() executionpolicy.LaunchPlan {
	return executionpolicy.LaunchPlan{
		RequestID: "req-000001", RequestDigest: strings.Repeat("a", 64), SessionID: "example-session", AttemptID: "attempt-000001",
		ExecutionIdentity: installconfig.Principal{Name: "awg-exec", Identifier: "1001", PrimaryGroupIdentifier: "1001"},
		Shell:             v1.ShellBash, Executable: "/usr/bin/bash", WorkingDirectory: "/home/alice/projects/demo", ApprovedRoot: "/home/alice/projects",
		Script: "printf 'SYNTHETIC-REQUEST-SCRIPT-9d61\\n'\n", TimeoutSeconds: 1, MaxOutputBytes: v1.MinOutputBytes,
		Artifacts:   []v1.ArtifactSelection{{Name: "results", Paths: []string{"reports/*.json"}}},
		Environment: []string{"HOME=/home/alice", "PATH=/usr/bin"}, Capabilities: []installconfig.Capability{},
	}
}

func completeArtifactManifest() v1.ArtifactManifest {
	return v1.ArtifactManifest{
		Status:    v1.ArtifactStatusComplete,
		Files:     []v1.ArtifactFile{{Group: "results", Path: "reports/result.json", SHA256: strings.Repeat("d", 64), SizeBytes: 17}},
		Omissions: []v1.ArtifactOmission{},
	}
}

func processWithExit(exit ProcessExit) *fakeProcess {
	channel := make(chan ProcessExit, 1)
	channel <- exit
	close(channel)
	return &fakeProcess{exit: channel}
}

func int64Ptr(value int64) *int64 { return &value }

func equalExitCode(left *int64, right *int64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
