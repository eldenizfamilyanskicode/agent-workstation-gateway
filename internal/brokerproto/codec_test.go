package brokerproto

import (
	"errors"
	"strings"
	"testing"

	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

func TestExecuteEnvelopeCanonicalRoundTrip(t *testing.T) {
	envelope := validExecuteEnvelope(t)
	encoded, err := MarshalCanonicalExecuteEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeExecuteEnvelope(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.AttemptID != envelope.AttemptID || decoded.AcceptedRequest.RequestDigest != envelope.AcceptedRequest.RequestDigest {
		t.Fatalf("execute envelope changed: %#v", decoded)
	}
}

func TestExecuteEnvelopeCannotExpressManagementAuthority(t *testing.T) {
	encoded, err := MarshalCanonicalExecuteEnvelope(validExecuteEnvelope(t))
	if err != nil {
		t.Fatal(err)
	}
	fields := []string{"run_as", "environment", "approved_roots", "capabilities", "repository", "update", "service", "acl"}
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			marker := "SYNTHETIC-" + strings.ToUpper(field) + "-4242"
			modified := strings.Replace(string(encoded), `"attempt_id":`, `"`+field+`":"`+marker+`","attempt_id":`, 1)
			_, err := DecodeExecuteEnvelope([]byte(modified))
			assertBrokerError(t, err, "envelope", "json-unknown-field")
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("broker error echoed management value: %q", err)
			}
		})
	}
}

func TestExecuteEnvelopeRejectsInvalidBindingAndBoundaries(t *testing.T) {
	tests := []struct {
		name  string
		alter func(*ExecuteEnvelope)
		field string
		rule  string
	}{
		{name: "version", alter: func(envelope *ExecuteEnvelope) { envelope.ProtocolVersion = 2 }, field: "protocol_version", rule: "unsupported-version"},
		{name: "operation", alter: func(envelope *ExecuteEnvelope) { envelope.Operation = "admin" }, field: "operation", rule: "unsupported-operation"},
		{name: "attempt", alter: func(envelope *ExecuteEnvelope) { envelope.AttemptID = "../other" }, field: "attempt_id", rule: "invalid-identifier"},
		{name: "accepted digest", alter: func(envelope *ExecuteEnvelope) { envelope.AcceptedRequest.RequestDigest = strings.Repeat("9", 64) }, field: "accepted_request", rule: "invalid-accepted-record"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope := validExecuteEnvelope(t)
			test.alter(&envelope)
			assertBrokerError(t, ValidateExecuteEnvelope(envelope), test.field, test.rule)
		})
	}

	_, err := DecodeExecuteEnvelope([]byte(strings.Repeat(" ", MaxExecuteEnvelopeBytes+1)))
	assertBrokerError(t, err, "envelope", "json-record-too-large")
}

func validExecuteEnvelope(t *testing.T) ExecuteEnvelope {
	t.Helper()
	request := v1.Request{
		ProtocolVersion:  v1.Version,
		RequestID:        "req-000001",
		SessionID:        "example-session",
		Actor:            "codex",
		Shell:            v1.ShellPwsh,
		WorkingDirectory: `C:\Users\Alice\Projects\demo`,
		Script:           "Get-ChildItem\n",
		TimeoutSeconds:   900,
		MaxOutputBytes:   1024 * 1024,
		Artifacts:        []v1.ArtifactSelection{},
	}
	digest, err := v1.DigestRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	return ExecuteEnvelope{
		ProtocolVersion: CurrentVersion,
		Operation:       OperationExecute,
		AttemptID:       "attempt-000001",
		AcceptedRequest: v1.AcceptedRequestRecord{
			ProtocolVersion: v1.Version,
			RequestID:       request.RequestID,
			RequestDigest:   digest,
			Request:         request,
			Issue: v1.IssueProvenance{
				Number: 42, NodeID: "ISSUE_node_42", SenderID: 1001, SenderLogin: "alice-example",
			},
			Workflow: v1.WorkflowProvenance{
				Repository: "alice/example-control", RunID: 9001, RunAttempt: 1,
				EventName: "issues", EventAction: "opened", HeadSHA: strings.Repeat("a", 40),
			},
			ControlSourceSHA: strings.Repeat("b", 40),
			AcceptedAt:       "2026-09-02T18:00:00Z",
		},
	}
}

func assertBrokerError(t *testing.T, err error, field string, rule string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected broker protocol error %s/%s", field, rule)
	}
	var validationFailure *Error
	if !errors.As(err, &validationFailure) {
		t.Fatalf("expected broker protocol error, got %T: %v", err, err)
	}
	if validationFailure.Field != field || validationFailure.Rule != rule {
		t.Fatalf("expected %s/%s, got %s/%s", field, rule, validationFailure.Field, validationFailure.Rule)
	}
}
