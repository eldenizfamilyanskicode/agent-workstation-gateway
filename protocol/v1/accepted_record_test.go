package v1

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAcceptedRequestRecordRoundTripAndDigest(t *testing.T) {
	record := validAcceptedRequestRecord(t)
	encoded, err := MarshalCanonicalAcceptedRequestRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := DecodeAcceptedRequestRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if roundTrip.RequestDigest != record.RequestDigest || roundTrip.Issue.NodeID != record.Issue.NodeID {
		t.Fatalf("accepted record changed: %#v", roundTrip)
	}
	digest, err := DigestAcceptedRequestRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if len(digest) != 64 {
		t.Fatalf("unexpected accepted record digest: %q", digest)
	}
}

func TestValidateAcceptedRequestRecordRejectsBindingAndProvenanceErrors(t *testing.T) {
	tests := []struct {
		name  string
		alter func(*AcceptedRequestRecord)
		field string
		rule  string
	}{
		{name: "request id mismatch", alter: func(record *AcceptedRequestRecord) { record.RequestID = "req-other" }, field: "request_id", rule: "does-not-match-request"},
		{name: "digest mismatch", alter: func(record *AcceptedRequestRecord) { record.RequestDigest = strings.Repeat("b", 64) }, field: "request_digest", rule: "does-not-match-request"},
		{name: "issue number", alter: func(record *AcceptedRequestRecord) { record.Issue.Number = 0 }, field: "issue.number", rule: "must-be-positive"},
		{name: "node id", alter: func(record *AcceptedRequestRecord) { record.Issue.NodeID = "node id" }, field: "issue.node_id", rule: "invalid-node-id"},
		{name: "sender id", alter: func(record *AcceptedRequestRecord) { record.Issue.SenderID = -1 }, field: "issue.sender_id", rule: "must-be-positive"},
		{name: "sender login", alter: func(record *AcceptedRequestRecord) { record.Issue.SenderLogin = "-alice" }, field: "issue.sender_login", rule: "invalid-login"},
		{name: "repository", alter: func(record *AcceptedRequestRecord) { record.Workflow.Repository = "repository-only" }, field: "workflow.repository", rule: "invalid-repository"},
		{name: "run id", alter: func(record *AcceptedRequestRecord) { record.Workflow.RunID = 0 }, field: "workflow.run_id", rule: "must-be-positive"},
		{name: "run attempt", alter: func(record *AcceptedRequestRecord) { record.Workflow.RunAttempt = 0 }, field: "workflow.run_attempt", rule: "must-be-positive"},
		{name: "event", alter: func(record *AcceptedRequestRecord) { record.Workflow.EventAction = "edited" }, field: "workflow.event", rule: "unexpected-event"},
		{name: "head sha", alter: func(record *AcceptedRequestRecord) { record.Workflow.HeadSHA = strings.Repeat("A", 40) }, field: "workflow.head_sha", rule: "invalid-lower-hex"},
		{name: "control sha", alter: func(record *AcceptedRequestRecord) { record.ControlSourceSHA = "short" }, field: "control_source_sha", rule: "invalid-lower-hex"},
		{name: "accepted timestamp", alter: func(record *AcceptedRequestRecord) { record.AcceptedAt = "2026-09-02T18:00:00+00:00" }, field: "accepted_at", rule: "not-canonical-utc"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := validAcceptedRequestRecord(t)
			test.alter(&record)
			assertProtocolError(t, ValidateAcceptedRequestRecord(record), ErrorKindValidation, test.field, test.rule)
		})
	}
}

func TestDecodeAcceptedRequestRecordIsStrictAndDoesNotEchoUnknownFields(t *testing.T) {
	record := validAcceptedRequestRecord(t)
	encoded := mustEncodeRecord(t, record)
	privateMarker := "SYNTHETIC-PRIVATE-ACCEPTED-4242"
	unknown := strings.Replace(string(encoded), `"accepted_at":`, `"`+privateMarker+`":true,"accepted_at":`, 1)
	_, err := DecodeAcceptedRequestRecord([]byte(unknown))
	assertProtocolError(t, err, ErrorKindDecode, "accepted_request", "schema-decode")
	if strings.Contains(err.Error(), privateMarker) {
		t.Fatalf("accepted decode error echoed private field: %q", err)
	}

	duplicate := strings.Replace(string(encoded), `"request_digest":"`+record.RequestDigest+`"`, `"request_digest":"`+record.RequestDigest+`","request_digest":"`+record.RequestDigest+`"`, 1)
	_, err = DecodeAcceptedRequestRecord([]byte(duplicate))
	assertProtocolError(t, err, ErrorKindDecode, "accepted_request", "duplicate-object-key")

	_, err = DecodeAcceptedRequestRecord(append(encoded, []byte(" {}")...))
	assertProtocolError(t, err, ErrorKindDecode, "accepted_request", "trailing-json")

	oversized := []byte(`{"padding":"` + strings.Repeat("x", MaxAcceptedRecordBytes) + `"}`)
	_, err = DecodeAcceptedRequestRecord(oversized)
	assertProtocolError(t, err, ErrorKindDecode, "accepted_request", "record-too-large")

	_, err = DecodeAcceptedRequestRecord([]byte{'{', '"', 0xff, '"', ':', '1', '}'})
	assertProtocolError(t, err, ErrorKindDecode, "accepted_request", "invalid-utf8")
}

func validAcceptedRequestRecord(t *testing.T) AcceptedRequestRecord {
	t.Helper()
	request := validRequest()
	digest, err := DigestRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	return AcceptedRequestRecord{
		ProtocolVersion: Version,
		RequestID:       request.RequestID,
		RequestDigest:   digest,
		Request:         request,
		Issue: IssueProvenance{
			Number:      42,
			NodeID:      "ISSUE_node_42",
			SenderID:    1001,
			SenderLogin: "alice-example",
		},
		Workflow: WorkflowProvenance{
			Repository:  "alice/example-control",
			RunID:       9001,
			RunAttempt:  1,
			EventName:   "issues",
			EventAction: "opened",
			HeadSHA:     strings.Repeat("a", 40),
		},
		ControlSourceSHA: strings.Repeat("b", 40),
		AcceptedAt:       "2026-09-02T18:00:00Z",
	}
}

func mustEncodeRecord(t *testing.T, record any) []byte {
	t.Helper()
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
