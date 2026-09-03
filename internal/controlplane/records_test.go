package controlplane

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

const testControlSHA = "1111111111111111111111111111111111111111"

func TestAcceptBindsImmutableIssueEvent(t *testing.T) {
	request := testRequest()
	encodedRequest, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	event := map[string]any{
		"action":               "opened",
		"issue":                map[string]any{"number": 17, "node_id": "I_kwDOExample", "body": string(encodedRequest)},
		"sender":               map[string]any{"id": 42, "login": "alice"},
		"ignored_github_field": true,
	}
	encodedEvent, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	record, err := Accept(encodedEvent, testWorkflow(), testControlSHA, time.Date(2026, 9, 3, 12, 0, 0, 0, time.FixedZone("offset", 4*60*60)))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(record.Request, request) || record.RequestID != request.RequestID || record.Issue.SenderLogin != "alice" ||
		record.AcceptedAt != "2026-09-03T08:00:00Z" || record.ControlSourceSHA != testControlSHA {
		t.Fatalf("unexpected accepted record: %#v", record)
	}
	if _, err := v1.MarshalCanonicalAcceptedRequestRecord(record); err != nil {
		t.Fatal(err)
	}
}

func TestAcceptFailsClosedWithoutEchoingRequest(t *testing.T) {
	marker := "private-request-marker"
	cases := []struct {
		name    string
		event   []byte
		context WorkflowContext
		sha     string
	}{
		{name: "oversized", event: []byte(strings.Repeat("x", MaxEventBytes+1)), context: testWorkflow(), sha: testControlSHA},
		{name: "wrong action", event: []byte(`{"action":"edited","issue":{},"sender":{}}`), context: testWorkflow(), sha: testControlSHA},
		{name: "bad request", event: []byte(`{"action":"opened","issue":{"number":1,"node_id":"node","body":"` + marker + `"},"sender":{"id":1,"login":"alice"}}`), context: testWorkflow(), sha: testControlSHA},
		{name: "bad context", event: testEvent(t), context: WorkflowContext{}, sha: testControlSHA},
		{name: "bad source", event: testEvent(t), context: testWorkflow(), sha: "main"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := Accept(test.event, test.context, test.sha, time.Now())
			if err == nil || strings.Contains(err.Error(), marker) {
				t.Fatalf("input was not rejected coarsely: %v", err)
			}
		})
	}
}

func TestFinalizeBindsAcceptanceWorkflow(t *testing.T) {
	accepted := acceptedRecord(t)
	zero := int64(0)
	report := v1.ExecutionReport{
		ProtocolVersion: v1.Version, RequestID: accepted.RequestID, RequestDigest: accepted.RequestDigest,
		AttemptID: "attempt-1", GatewaySourceSHA: strings.Repeat("2", 40), CommandStatus: v1.CommandStatusCompleted,
		ExitCode: &zero, StartedAt: "2026-09-03T08:00:01Z", FinishedAt: "2026-09-03T08:00:02Z", DurationMilliseconds: 1000,
		Stdout:    v1.OutputMetadata{SHA256: strings.Repeat("3", 64), TotalBytes: 0, RetainedBytes: 0, Truncated: false},
		Stderr:    v1.OutputMetadata{SHA256: strings.Repeat("3", 64), TotalBytes: 0, RetainedBytes: 0, Truncated: false},
		Artifacts: v1.ArtifactManifest{Status: v1.ArtifactStatusNotRequested, Files: []v1.ArtifactFile{}, Omissions: []v1.ArtifactOmission{}},
	}
	result, err := Finalize(accepted, report, testWorkflow(), time.Date(2026, 9, 3, 8, 0, 3, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if result.FinalizedAt != "2026-09-03T08:00:03Z" || result.Workflow != accepted.Workflow {
		t.Fatalf("unexpected result: %#v", result)
	}

	wrong := testWorkflow()
	wrong.RunID = "99"
	if _, err := Finalize(accepted, report, wrong, time.Now()); err == nil {
		t.Fatal("mismatched finalization run was accepted")
	}
}

func acceptedRecord(t *testing.T) v1.AcceptedRequestRecord {
	t.Helper()
	record, err := Accept(testEvent(t), testWorkflow(), testControlSHA, time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func testEvent(t *testing.T) []byte {
	t.Helper()
	request, err := json.Marshal(testRequest())
	if err != nil {
		t.Fatal(err)
	}
	event, err := json.Marshal(map[string]any{
		"action": "opened",
		"issue":  map[string]any{"number": 17, "node_id": "I_kwDOExample", "body": string(request)},
		"sender": map[string]any{"id": 42, "login": "alice"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func testWorkflow() WorkflowContext {
	return WorkflowContext{
		Repository: "alice/example-control", RunID: "7", RunAttempt: "1", EventName: "issues",
		EventAction: "opened", HeadSHA: strings.Repeat("4", 40),
	}
}

func testRequest() v1.Request {
	return v1.Request{
		ProtocolVersion: v1.Version, RequestID: "req-1", SessionID: "session-1", Actor: "alice",
		Operation: v1.RequestOperationExecute, ProcessID: "",
		Shell: v1.ShellPowerShell, WorkingDirectory: `C:\Users\Alice\Projects`, Script: "Write-Output hello",
		TimeoutSeconds: 30, MaxOutputBytes: 4096, Artifacts: []v1.ArtifactSelection{},
	}
}
