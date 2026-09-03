package executionrun

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionpolicy"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

func TestBackgroundStartStatusLogsStopLifecycle(t *testing.T) {
	terminated := ProcessExit{Code: 23}
	process := &fakeProcess{exit: make(chan ProcessExit, 1), terminateExit: &terminated}
	launcher := &fakeLauncher{process: process, stdout: []byte("server-ready\n"), stderr: []byte("server-warning\n")}
	runner := mustRunner(t, launcher, nil, &fakeTimerFactory{})

	start := backgroundPlan(v1.RequestOperationStart)
	startOutput, err := runner.Run(context.Background(), start, strings.Repeat("c", 40))
	if err != nil {
		t.Fatal(err)
	}
	assertBackgroundOperation(t, startOutput, backgroundRunning)
	if launcher.calls != 1 || launcher.launch.ExecutionIdentity != start.ExecutionIdentity ||
		launcher.launch.WorkingDirectory != start.WorkingDirectory {
		t.Fatalf("background launch escaped authorized plan: %#v", launcher.launch)
	}

	statusOutput, err := runner.Run(context.Background(), backgroundPlan(v1.RequestOperationStatus), strings.Repeat("c", 40))
	if err != nil {
		t.Fatal(err)
	}
	statusHeader := assertBackgroundOperation(t, statusOutput, backgroundRunning)
	if statusHeader.Stdout.TotalBytes != int64(len("server-ready\n")) || statusHeader.Stderr.TotalBytes != int64(len("server-warning\n")) {
		t.Fatalf("status lost bounded log metadata: %#v", statusHeader)
	}

	logsOutput, err := runner.Run(context.Background(), backgroundPlan(v1.RequestOperationLogs), strings.Repeat("c", 40))
	if err != nil {
		t.Fatal(err)
	}
	assertBackgroundOperation(t, logsOutput, backgroundRunning)
	if !bytes.Contains(logsOutput.Stdout, []byte("server-ready\n")) || string(logsOutput.Stderr) != "server-warning\n" {
		t.Fatalf("logs response lost retained streams: %q / %q", logsOutput.Stdout, logsOutput.Stderr)
	}

	stopOutput, err := runner.Run(context.Background(), backgroundPlan(v1.RequestOperationStop), strings.Repeat("c", 40))
	if err != nil {
		t.Fatal(err)
	}
	stopHeader := assertBackgroundOperation(t, stopOutput, backgroundStopped)
	if stopHeader.ExitCode == nil || *stopHeader.ExitCode != 23 || process.terminations() != 1 {
		t.Fatalf("stop did not synchronously reap the tree: %#v / %d", stopHeader, process.terminations())
	}

	missing, err := runner.Run(context.Background(), backgroundPlan(v1.RequestOperationStatus), strings.Repeat("c", 40))
	if err != nil {
		t.Fatal(err)
	}
	if missing.Report.CommandStatus != v1.CommandStatusFailed || missing.Report.ExitCode == nil || *missing.Report.ExitCode != 1 {
		t.Fatalf("removed process remained addressable: %#v", missing.Report)
	}
}

func TestBackgroundOwnershipAndDuplicateAreClosed(t *testing.T) {
	process := &fakeProcess{exit: make(chan ProcessExit, 1)}
	runner := mustRunner(t, &fakeLauncher{process: process}, nil, &fakeTimerFactory{})
	if _, err := runner.Run(context.Background(), backgroundPlan(v1.RequestOperationStart), strings.Repeat("c", 40)); err != nil {
		t.Fatal(err)
	}
	duplicate, err := runner.Run(context.Background(), backgroundPlan(v1.RequestOperationStart), strings.Repeat("c", 40))
	if err != nil || duplicate.Report.CommandStatus != v1.CommandStatusFailed {
		t.Fatalf("duplicate start did not fail closed: %#v / %v", duplicate.Report, err)
	}
	for _, alter := range []func(*executionpolicy.LaunchPlan){
		func(plan *executionpolicy.LaunchPlan) { plan.SessionID = "other-session" },
		func(plan *executionpolicy.LaunchPlan) { plan.WorkingDirectory = "/home/alice/projects/other" },
	} {
		plan := backgroundPlan(v1.RequestOperationLogs)
		alter(&plan)
		output, runErr := runner.Run(context.Background(), plan, strings.Repeat("c", 40))
		if runErr != nil || output.Report.CommandStatus != v1.CommandStatusFailed {
			t.Fatalf("foreign lifecycle lookup was admitted: %#v / %v", output.Report, runErr)
		}
	}
}

func TestBackgroundTimeoutAndRunnerCloseReapTrees(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		process := &fakeProcess{exit: make(chan ProcessExit, 1)}
		runner := mustRunner(t, &fakeLauncher{process: process}, nil, &fakeTimerFactory{fire: true})
		if _, err := runner.Run(context.Background(), backgroundPlan(v1.RequestOperationStart), strings.Repeat("c", 40)); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(time.Second)
		for process.terminations() == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		output, err := runner.Run(context.Background(), backgroundPlan(v1.RequestOperationStatus), strings.Repeat("c", 40))
		if err != nil {
			t.Fatal(err)
		}
		assertBackgroundOperation(t, output, backgroundTimedOut)
		if process.terminations() != 1 {
			t.Fatalf("timed-out background tree termination count: %d", process.terminations())
		}
	})

	t.Run("close", func(t *testing.T) {
		terminated := ProcessExit{Code: 24}
		process := &fakeProcess{exit: make(chan ProcessExit, 1), terminateExit: &terminated}
		runner := mustRunner(t, &fakeLauncher{process: process}, nil, &fakeTimerFactory{})
		if _, err := runner.Run(context.Background(), backgroundPlan(v1.RequestOperationStart), strings.Repeat("c", 40)); err != nil {
			t.Fatal(err)
		}
		if err := runner.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if process.terminations() != 1 {
			t.Fatalf("runner close did not reap background tree: %d", process.terminations())
		}
	})
}

func backgroundPlan(operation v1.RequestOperation) executionpolicy.LaunchPlan {
	plan := validLaunchPlan()
	plan.Operation = operation
	plan.ProcessID = "dev-server"
	plan.Artifacts = []v1.ArtifactSelection{}
	if operation != v1.RequestOperationStart {
		plan.Script = "-"
	}
	return plan
}

func assertBackgroundOperation(t *testing.T, output Output, expectedState string) backgroundHeader {
	t.Helper()
	if err := v1.ValidateExecutionReport(output.Report); err != nil {
		t.Fatalf("invalid background report: %v", err)
	}
	if output.Report.CommandStatus != v1.CommandStatusCompleted || output.Report.ExitCode == nil || *output.Report.ExitCode != 0 {
		t.Fatalf("unexpected lifecycle operation outcome: %#v", output.Report)
	}
	line := bytes.SplitN(output.Stdout, []byte{'\n'}, 2)[0]
	var header backgroundHeader
	if err := json.Unmarshal(line, &header); err != nil {
		t.Fatalf("invalid background header %q: %v", line, err)
	}
	if header.ProcessID != "dev-server" || header.State != expectedState {
		t.Fatalf("unexpected background header: %#v", header)
	}
	return header
}
