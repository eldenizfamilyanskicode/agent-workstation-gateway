package v1

import (
	"strings"
	"testing"
)

func TestExecutionReportCanonicalRoundTripAndDigest(t *testing.T) {
	report := validExecutionReport(t)
	encoded, err := MarshalCanonicalExecutionReport(report)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeExecutionReport(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.AttemptID != report.AttemptID || decoded.RequestDigest != report.RequestDigest {
		t.Fatalf("execution report changed: %#v", decoded)
	}
	digest, err := DigestExecutionReport(report)
	if err != nil || len(digest) != 64 {
		t.Fatalf("invalid execution report digest %q: %v", digest, err)
	}
}

func TestExecutionReportCannotClaimFinalizationAuthority(t *testing.T) {
	encoded := string(mustEncodeRecord(t, validExecutionReport(t)))
	fields := []string{"finalized_at", "workflow", "repository_write_token"}
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			marker := "SYNTHETIC-FINALIZER-VALUE-4242"
			modified := strings.Replace(encoded, `"artifacts":`, `"`+field+`":"`+marker+`","artifacts":`, 1)
			_, err := DecodeExecutionReport([]byte(modified))
			assertProtocolError(t, err, ErrorKindDecode, "execution_report", "schema-decode")
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("execution report error echoed finalizer value: %q", err)
			}
		})
	}
}

func TestDecodeExecutionReportRequiresZeroValuedFields(t *testing.T) {
	encoded := string(mustEncodeRecord(t, validExecutionReport(t)))
	tests := []string{
		strings.Replace(encoded, `"exit_code":0,`, "", 1),
		strings.Replace(encoded, `,"truncated":false`, "", 1),
	}
	for _, modified := range tests {
		_, err := DecodeExecutionReport([]byte(modified))
		assertProtocolError(t, err, ErrorKindDecode, "execution_report", "missing-required-field")
	}
}

func TestFinalizeResultRecordAddsHostedAuthority(t *testing.T) {
	accepted := validAcceptedRequestRecord(t)
	report := validExecutionReport(t)
	workflow := accepted.Workflow
	workflow.RunAttempt++
	result, err := FinalizeResultRecord(accepted, report, "2026-09-02T18:00:03Z", workflow)
	if err != nil {
		t.Fatal(err)
	}
	if result.FinalizedAt != "2026-09-02T18:00:03Z" || result.Workflow.RunAttempt != 2 {
		t.Fatalf("finalizer authority was not added: %#v", result)
	}
	if err := ValidateResultBinding(accepted, result); err != nil {
		t.Fatalf("finalized result is not bound: %v", err)
	}
}

func TestFinalizeResultRecordRejectsUnboundOrInvalidAuthority(t *testing.T) {
	accepted := validAcceptedRequestRecord(t)
	tests := []struct {
		name          string
		alterAccepted func(*AcceptedRequestRecord)
		alterReport   func(*ExecutionReport)
		finalizedAt   string
		alterFlow     func(*WorkflowProvenance)
		field         string
		rule          string
	}{
		{name: "digest", alterReport: func(report *ExecutionReport) { report.RequestDigest = strings.Repeat("9", 64) }, finalizedAt: "2026-09-02T18:00:03Z", alterFlow: func(*WorkflowProvenance) {}, field: "request_digest", rule: "does-not-match-accepted-request"},
		{name: "early finalization", alterReport: func(*ExecutionReport) {}, finalizedAt: "2026-09-02T17:59:59Z", alterFlow: func(*WorkflowProvenance) {}, field: "finalized_at", rule: "before-finished-at"},
		{name: "workflow", alterReport: func(*ExecutionReport) {}, finalizedAt: "2026-09-02T18:00:03Z", alterFlow: func(workflow *WorkflowProvenance) { workflow.RunID++ }, field: "workflow", rule: "does-not-match-acceptance-run"},
		{name: "earlier workflow attempt", alterReport: func(*ExecutionReport) {}, finalizedAt: "2026-09-02T18:00:03Z", alterFlow: func(workflow *WorkflowProvenance) { workflow.RunAttempt = 1 }, field: "workflow", rule: "does-not-match-acceptance-run", alterAccepted: func(accepted *AcceptedRequestRecord) { accepted.Workflow.RunAttempt = 2 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			acceptedForTest := accepted
			if test.alterAccepted != nil {
				test.alterAccepted(&acceptedForTest)
			}
			report := validExecutionReport(t)
			test.alterReport(&report)
			workflow := acceptedForTest.Workflow
			test.alterFlow(&workflow)
			_, err := FinalizeResultRecord(acceptedForTest, report, test.finalizedAt, workflow)
			assertProtocolError(t, err, ErrorKindValidation, test.field, test.rule)
		})
	}
}

func validExecutionReport(t *testing.T) ExecutionReport {
	t.Helper()
	return executionReportFromResult(validResultRecord(t))
}
