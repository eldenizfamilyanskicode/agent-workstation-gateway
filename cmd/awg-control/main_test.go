package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

const testSourceSHA = "1111111111111111111111111111111111111111"

func TestAcceptAndFinalizeCommands(t *testing.T) {
	directory := t.TempDir()
	eventPath := filepath.Join(directory, "event.json")
	acceptedPath := filepath.Join(directory, "accepted.json")
	reportPath := filepath.Join(directory, "report.json")
	resultPath := filepath.Join(directory, "result.json")
	request := v1.Request{
		ProtocolVersion: v1.Version, RequestID: "req-1", SessionID: "session-1", Actor: "alice", Shell: v1.ShellPowerShell,
		WorkingDirectory: `C:\Users\Alice\Projects`, Script: "Write-Output hello", TimeoutSeconds: 30,
		MaxOutputBytes: 4096, Artifacts: []v1.ArtifactSelection{},
	}
	requestBytes, _ := json.Marshal(request)
	eventBytes, _ := json.Marshal(map[string]any{
		"action": "opened", "issue": map[string]any{"number": 1, "node_id": "I_example", "body": string(requestBytes)},
		"sender": map[string]any{"id": 2, "login": "alice"},
	})
	if err := os.WriteFile(eventPath, eventBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	environment := workflowEnvironment()
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	if exit := run(context.Background(), []string{"accept", "--event", eventPath, "--output", acceptedPath}, stdout, stderr, consumeMap(environment), testSourceSHA, fixedTime); exit != 0 {
		t.Fatalf("accept failed: exit=%d stderr=%q", exit, stderr.String())
	}
	acceptedBytes, err := os.ReadFile(acceptedPath)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := v1.DecodeAcceptedRequestRecord(acceptedBytes)
	if err != nil {
		t.Fatal(err)
	}
	zero := int64(0)
	report := v1.ExecutionReport{
		ProtocolVersion: v1.Version, RequestID: accepted.RequestID, RequestDigest: accepted.RequestDigest,
		AttemptID: "attempt-1", GatewaySourceSHA: strings.Repeat("2", 40), CommandStatus: v1.CommandStatusCompleted,
		ExitCode: &zero, StartedAt: "2026-09-03T08:00:00Z", FinishedAt: "2026-09-03T08:00:00Z", DurationMilliseconds: 0,
		Stdout: v1.OutputMetadata{SHA256: strings.Repeat("3", 64)}, Stderr: v1.OutputMetadata{SHA256: strings.Repeat("3", 64)},
		Artifacts: v1.ArtifactManifest{Status: v1.ArtifactStatusNotRequested, Files: []v1.ArtifactFile{}, Omissions: []v1.ArtifactOmission{}},
	}
	reportBytes, err := v1.MarshalCanonicalExecutionReport(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reportPath, reportBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if exit := run(context.Background(), []string{"finalize", "--accepted", acceptedPath, "--report", reportPath, "--output", resultPath}, stdout, stderr, consumeMap(workflowEnvironment()), testSourceSHA, fixedTime); exit != 0 {
		t.Fatalf("finalize failed: exit=%d stderr=%q", exit, stderr.String())
	}
	resultBytes, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v1.DecodeResultRecord(resultBytes); err != nil {
		t.Fatal(err)
	}
}

func TestCommandsRejectBadInputsWithoutEchoingPaths(t *testing.T) {
	markerPath := filepath.Join(t.TempDir(), "private-marker")
	for _, args := range [][]string{
		{"accept", "--event", markerPath, "--output", markerPath + ".out"},
		{"finalize", "--accepted", markerPath, "--report", markerPath, "--output", markerPath + ".out"},
		{"publish", "--kind", "accepted", "--input", markerPath},
	} {
		stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
		exit := run(context.Background(), args, stdout, stderr, consumeMap(map[string]string{}), testSourceSHA, fixedTime)
		if exit == 0 || strings.Contains(stderr.String(), markerPath) {
			t.Fatalf("unsafe rejection: exit=%d stderr=%q", exit, stderr.String())
		}
	}
}

func workflowEnvironment() map[string]string {
	return map[string]string{
		"GITHUB_REPOSITORY": "alice/example-control", "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1",
		"GITHUB_EVENT_NAME": "issues", "GITHUB_SHA": strings.Repeat("4", 40),
	}
}

func consumeMap(values map[string]string) consumeEnvironment {
	return func(name string) (string, bool) {
		value, exists := values[name]
		delete(values, name)
		return value, exists
	}
}

func fixedTime() time.Time { return time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC) }
