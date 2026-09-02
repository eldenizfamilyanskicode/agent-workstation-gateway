package v1

import (
	"fmt"
	"strings"
	"testing"
)

func TestValidateResultRecordAcceptsEveryCommandStatus(t *testing.T) {
	tests := []struct {
		status   CommandStatus
		exitCode *int64
	}{
		{status: CommandStatusCompleted, exitCode: int64Pointer(0)},
		{status: CommandStatusFailed, exitCode: int64Pointer(17)},
		{status: CommandStatusTimedOut, exitCode: nil},
		{status: CommandStatusCancelled, exitCode: nil},
		{status: CommandStatusRuntimeFailed, exitCode: nil},
	}
	for _, test := range tests {
		t.Run(string(test.status), func(t *testing.T) {
			record := validResultRecord(t)
			record.CommandStatus = test.status
			record.ExitCode = test.exitCode
			if err := ValidateResultRecord(record); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestValidateResultRecordRejectsCommandStatusExitCodeMismatch(t *testing.T) {
	tests := []struct {
		name     string
		status   CommandStatus
		exitCode *int64
		rule     string
	}{
		{name: "unknown", status: "unknown", exitCode: nil, rule: "unsupported-status"},
		{name: "completed missing", status: CommandStatusCompleted, exitCode: nil, rule: "completed-requires-zero"},
		{name: "completed nonzero", status: CommandStatusCompleted, exitCode: int64Pointer(1), rule: "completed-requires-zero"},
		{name: "failed zero", status: CommandStatusFailed, exitCode: int64Pointer(0), rule: "failed-requires-platform-code"},
		{name: "failed too large", status: CommandStatusFailed, exitCode: int64Pointer(4294967296), rule: "failed-requires-platform-code"},
		{name: "timeout exit", status: CommandStatusTimedOut, exitCode: int64Pointer(124), rule: "status-requires-null"},
		{name: "cancelled exit", status: CommandStatusCancelled, exitCode: int64Pointer(1), rule: "status-requires-null"},
		{name: "runtime exit", status: CommandStatusRuntimeFailed, exitCode: int64Pointer(125), rule: "status-requires-null"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := validResultRecord(t)
			record.CommandStatus = test.status
			record.ExitCode = test.exitCode
			field := "exit_code"
			if test.rule == "unsupported-status" {
				field = "command_status"
			}
			assertProtocolError(t, ValidateResultRecord(record), ErrorKindValidation, field, test.rule)
		})
	}
}

func TestValidateResultRecordTimingAndOutputInvariants(t *testing.T) {
	tests := []struct {
		name  string
		alter func(*ResultRecord)
		field string
		rule  string
	}{
		{name: "non utc", alter: func(record *ResultRecord) { record.StartedAt = "2026-09-02T18:00:00+00:00" }, field: "started_at", rule: "not-canonical-utc"},
		{name: "finish before start", alter: func(record *ResultRecord) { record.FinishedAt = "2026-09-02T17:59:59Z" }, field: "finished_at", rule: "before-started-at"},
		{name: "duration", alter: func(record *ResultRecord) { record.DurationMilliseconds = 999 }, field: "duration_ms", rule: "does-not-match-timestamps"},
		{name: "finalized early", alter: func(record *ResultRecord) { record.FinalizedAt = "2026-09-02T17:59:59Z" }, field: "finalized_at", rule: "before-finished-at"},
		{name: "stdout digest", alter: func(record *ResultRecord) { record.Stdout.SHA256 = strings.Repeat("A", 64) }, field: "stdout.sha256", rule: "invalid-lower-hex"},
		{name: "stdout total", alter: func(record *ResultRecord) { record.Stdout.TotalBytes = -1 }, field: "stdout.total_bytes", rule: "negative"},
		{name: "retained above total", alter: func(record *ResultRecord) { record.Stdout.RetainedBytes = 2 }, field: "stdout.retained_bytes", rule: "outside-total-bytes"},
		{name: "truncated without omission", alter: func(record *ResultRecord) { record.Stdout.Truncated = true }, field: "stdout.truncated", rule: "requires-omitted-bytes"},
		{name: "untruncated missing bytes", alter: func(record *ResultRecord) { record.Stdout.TotalBytes = 2 }, field: "stdout.truncated", rule: "false-requires-all-bytes"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := validResultRecord(t)
			test.alter(&record)
			assertProtocolError(t, ValidateResultRecord(record), ErrorKindValidation, test.field, test.rule)
		})
	}

	record := validResultRecord(t)
	record.Stdout = OutputMetadata{
		SHA256:        strings.Repeat("e", 64),
		TotalBytes:    MaxOutputBytes,
		RetainedBytes: MaxOutputBytes - 1,
		Truncated:     true,
	}
	if err := ValidateResultRecord(record); err != nil {
		t.Fatalf("valid truncated output rejected: %v", err)
	}
}

func TestValidateResultRecordAcceptsFullStreamCountBeyondRetainedLimit(t *testing.T) {
	record := validResultRecord(t)
	record.Stdout = OutputMetadata{
		SHA256:        strings.Repeat("d", 64),
		TotalBytes:    int64(MaxOutputBytes) + 1,
		RetainedBytes: MaxOutputBytes,
		Truncated:     true,
	}
	if err := ValidateResultRecord(record); err != nil {
		t.Fatalf("complete observed stream metadata was rejected: %v", err)
	}
}

func TestResultRecordRoundTripDigestAndStrictDecoding(t *testing.T) {
	record := validResultRecord(t)
	encoded, err := MarshalCanonicalResultRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := DecodeResultRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if roundTrip.AttemptID != record.AttemptID || *roundTrip.ExitCode != *record.ExitCode {
		t.Fatalf("result changed: %#v", roundTrip)
	}
	digest, err := DigestResultRecord(record)
	if err != nil || len(digest) != 64 {
		t.Fatalf("invalid result digest %q: %v", digest, err)
	}

	privateMarker := "SYNTHETIC-PRIVATE-RESULT-4242"
	unknown := strings.Replace(string(encoded), `"finalized_at":`, `"`+privateMarker+`":true,"finalized_at":`, 1)
	_, err = DecodeResultRecord([]byte(unknown))
	assertProtocolError(t, err, ErrorKindDecode, "result", "schema-decode")
	if strings.Contains(err.Error(), privateMarker) {
		t.Fatalf("result decode error echoed private field: %q", err)
	}
	caseVariant := strings.Replace(string(encoded), `"attempt_id":`, `"ATTEMPT_ID":`, 1)
	_, err = DecodeResultRecord([]byte(caseVariant))
	assertProtocolError(t, err, ErrorKindDecode, "result", "schema-decode")

	duplicate := strings.Replace(string(encoded), `"attempt_id":"attempt-000001"`, `"attempt_id":"attempt-000001","attempt_id":"attempt-000002"`, 1)
	_, err = DecodeResultRecord([]byte(duplicate))
	assertProtocolError(t, err, ErrorKindDecode, "result", "duplicate-object-key")

	_, err = DecodeResultRecord(append(encoded, []byte(" {}")...))
	assertProtocolError(t, err, ErrorKindDecode, "result", "trailing-json")

	oversized := []byte(`{"padding":"` + strings.Repeat("x", MaxResultRecordBytes) + `"}`)
	_, err = DecodeResultRecord(oversized)
	assertProtocolError(t, err, ErrorKindDecode, "result", "record-too-large")

	_, err = DecodeResultRecord([]byte{'{', '"', 0xff, '"', ':', '1', '}'})
	assertProtocolError(t, err, ErrorKindDecode, "result", "invalid-utf8")
}

func TestDecodeResultRecordRequiresZeroValuedFields(t *testing.T) {
	record := validResultRecord(t)
	encoded := string(mustEncodeRecord(t, record))
	tests := []struct {
		name    string
		encoded string
		rule    string
	}{
		{name: "exit code", encoded: strings.Replace(encoded, `"exit_code":0,`, "", 1), rule: "missing-required-field"},
		{name: "duration", encoded: strings.Replace(encoded, `"duration_ms":1000,`, "", 1), rule: "missing-required-field"},
		{name: "output truncation", encoded: strings.Replace(encoded, `,"truncated":false`, "", 1), rule: "missing-required-field"},
		{name: "null output truncation", encoded: strings.Replace(encoded, `"truncated":false`, `"truncated":null`, 1), rule: "schema-decode"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeResultRecord([]byte(test.encoded))
			assertProtocolError(t, err, ErrorKindDecode, "result", test.rule)
		})
	}
}

func TestValidateResultBinding(t *testing.T) {
	accepted := validAcceptedRequestRecord(t)
	result := validResultRecord(t)
	if err := ValidateResultBinding(accepted, result); err != nil {
		t.Fatalf("valid accepted/result binding rejected: %v", err)
	}

	tests := []struct {
		name  string
		alter func(*ResultRecord)
		field string
		rule  string
	}{
		{name: "request id", alter: func(record *ResultRecord) { record.RequestID = "req-other" }, field: "request_id", rule: "does-not-match-accepted-request"},
		{name: "request digest", alter: func(record *ResultRecord) { record.RequestDigest = strings.Repeat("9", 64) }, field: "request_digest", rule: "does-not-match-accepted-request"},
		{name: "repository", alter: func(record *ResultRecord) { record.Workflow.Repository = "alice/other-control" }, field: "workflow", rule: "does-not-match-acceptance-run"},
		{name: "run id", alter: func(record *ResultRecord) { record.Workflow.RunID++ }, field: "workflow", rule: "does-not-match-acceptance-run"},
		{name: "head sha", alter: func(record *ResultRecord) { record.Workflow.HeadSHA = strings.Repeat("9", 40) }, field: "workflow", rule: "does-not-match-acceptance-run"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modified := result
			test.alter(&modified)
			assertProtocolError(t, ValidateResultBinding(accepted, modified), ErrorKindValidation, test.field, test.rule)
		})
	}

	resultRetry := result
	resultRetry.Workflow.RunAttempt = accepted.Workflow.RunAttempt + 1
	if err := ValidateResultBinding(accepted, resultRetry); err != nil {
		t.Fatalf("same-run finalization retry rejected: %v", err)
	}
}

func TestValidateResultBindingEnforcesAcceptedLimitsAndArtifactGroups(t *testing.T) {
	accepted := validAcceptedRequestRecord(t)
	result := validResultRecord(t)

	result.Stdout = OutputMetadata{
		SHA256:        strings.Repeat("d", 64),
		TotalBytes:    int64(accepted.Request.MaxOutputBytes + 2),
		RetainedBytes: int64(accepted.Request.MaxOutputBytes + 1),
		Truncated:     true,
	}
	assertProtocolError(t, ValidateResultBinding(accepted, result), ErrorKindValidation, "stdout.retained_bytes", "exceeds-accepted-output-limit")

	result = validResultRecord(t)
	result.Artifacts = ArtifactManifest{Status: ArtifactStatusComplete, Files: []ArtifactFile{validArtifactFile()}, Omissions: []ArtifactOmission{}}
	assertProtocolError(t, ValidateResultBinding(accepted, result), ErrorKindValidation, "artifacts.status", "artifacts-not-requested")

	accepted.Request.Artifacts = []ArtifactSelection{{Name: "results", Paths: []string{"reports/**/*.json"}}}
	accepted.RequestDigest = mustRequestDigest(t, accepted.Request)
	result = validResultRecord(t)
	result.RequestDigest = accepted.RequestDigest
	assertProtocolError(t, ValidateResultBinding(accepted, result), ErrorKindValidation, "artifacts.status", "requested-artifacts-not-represented")

	result.Artifacts = ArtifactManifest{Status: ArtifactStatusComplete, Files: []ArtifactFile{validArtifactFile()}, Omissions: []ArtifactOmission{}}
	result.Artifacts.Files[0].Group = "other"
	assertProtocolError(t, ValidateResultBinding(accepted, result), ErrorKindValidation, "artifacts.files.group", "not-in-accepted-request")

	result.Artifacts = ArtifactManifest{Status: ArtifactStatusFailed, Files: []ArtifactFile{}, Omissions: []ArtifactOmission{validArtifactOmission()}}
	result.Artifacts.Omissions[0].Group = "other"
	assertProtocolError(t, ValidateResultBinding(accepted, result), ErrorKindValidation, "artifacts.omissions.group", "not-in-accepted-request")
}

func TestMarshalCanonicalResultRecordEnforcesSizeLimit(t *testing.T) {
	record := validResultRecord(t)
	record.Artifacts = ArtifactManifest{
		Status:    ArtifactStatusComplete,
		Files:     make([]ArtifactFile, MaxArtifactFiles),
		Omissions: []ArtifactOmission{},
	}
	for index := range record.Artifacts.Files {
		record.Artifacts.Files[index] = ArtifactFile{
			Group:     "results",
			Path:      fmt.Sprintf("file-%03d-%s", index, strings.Repeat("x", MaxArtifactFilePathBytes-9)),
			SHA256:    strings.Repeat("f", 64),
			SizeBytes: 1,
		}
	}

	_, err := MarshalCanonicalResultRecord(record)
	assertProtocolError(t, err, ErrorKindValidation, "result", "canonical-size-limit")
}

func validResultRecord(t *testing.T) ResultRecord {
	t.Helper()
	requestDigest, err := DigestRequest(validRequest())
	if err != nil {
		t.Fatal(err)
	}
	return ResultRecord{
		ProtocolVersion:      Version,
		RequestID:            "req-000001",
		RequestDigest:        requestDigest,
		AttemptID:            "attempt-000001",
		GatewaySourceSHA:     strings.Repeat("c", 40),
		CommandStatus:        CommandStatusCompleted,
		ExitCode:             int64Pointer(0),
		StartedAt:            "2026-09-02T18:00:00Z",
		FinishedAt:           "2026-09-02T18:00:01Z",
		DurationMilliseconds: 1000,
		Stdout:               OutputMetadata{SHA256: strings.Repeat("d", 64), TotalBytes: 1, RetainedBytes: 1, Truncated: false},
		Stderr:               OutputMetadata{SHA256: strings.Repeat("e", 64), TotalBytes: 0, RetainedBytes: 0, Truncated: false},
		Artifacts:            ArtifactManifest{Status: ArtifactStatusNotRequested, Files: []ArtifactFile{}, Omissions: []ArtifactOmission{}},
		FinalizedAt:          "2026-09-02T18:00:02Z",
		Workflow: WorkflowProvenance{
			Repository:  "alice/example-control",
			RunID:       9001,
			RunAttempt:  1,
			EventName:   "issues",
			EventAction: "opened",
			HeadSHA:     strings.Repeat("a", 40),
		},
	}
}

func validArtifactFile() ArtifactFile {
	return ArtifactFile{Group: "results", Path: "reports/result.json", SHA256: strings.Repeat("f", 64), SizeBytes: 128}
}

func validArtifactOmission() ArtifactOmission {
	return ArtifactOmission{Group: "results", Pattern: "reports/**/*.json", Reason: ArtifactOmissionNoMatch}
}

func int64Pointer(value int64) *int64 {
	return &value
}

func mustRequestDigest(t *testing.T, request Request) string {
	t.Helper()
	digest, err := DigestRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
