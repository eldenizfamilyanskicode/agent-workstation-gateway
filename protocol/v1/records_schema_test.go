package v1

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

func TestAcceptedRequestSchemaIsStrictAndMatchesContract(t *testing.T) {
	schema := parseSchema(t, "accepted-request.schema.json")
	assertStrictSchemaObject(t, "accepted request", schema)
	assertSchemaRootNumber(t, schema, "x-awg-max-encoded-bytes", MaxAcceptedRecordBytes)
	assertRequiredFields(t, schema, []string{
		"accepted_at", "control_source_sha", "issue", "protocol_version", "request",
		"request_digest", "request_id", "workflow",
	})

	properties := objectValue(t, schema["properties"])
	requestReference := objectValue(t, properties["request"])
	if requestReference["$ref"] != "request.schema.json" {
		t.Fatalf("accepted schema does not reference the request contract: %#v", requestReference)
	}
	definitions := objectValue(t, schema["$defs"])
	assertStrictSchemaObject(t, "issue provenance", objectValue(t, definitions["issue_provenance"]))
	assertStrictSchemaObject(t, "workflow provenance", objectValue(t, definitions["workflow_provenance"]))
}

func TestResultSchemaIsStrictAndMatchesContract(t *testing.T) {
	schema := parseSchema(t, "result.schema.json")
	assertStrictSchemaObject(t, "result", schema)
	assertSchemaRootNumber(t, schema, "x-awg-max-encoded-bytes", MaxResultRecordBytes)
	assertRequiredFields(t, schema, []string{
		"artifacts", "attempt_id", "command_status", "duration_ms", "exit_code", "finalized_at",
		"finished_at", "gateway_source_sha", "protocol_version", "request_digest", "request_id",
		"started_at", "stderr", "stdout", "workflow",
	})

	properties := objectValue(t, schema["properties"])
	assertSchemaEnum(t, objectValue(t, properties["command_status"]), []string{
		string(CommandStatusCancelled), string(CommandStatusCompleted), string(CommandStatusFailed),
		string(CommandStatusRuntimeFailed), string(CommandStatusTimedOut),
	})

	definitions := objectValue(t, schema["$defs"])
	output := objectValue(t, definitions["output_metadata"])
	assertStrictSchemaObject(t, "output metadata", output)
	outputProperties := objectValue(t, output["properties"])
	if _, present := objectValue(t, outputProperties["total_bytes"])["maximum"]; present {
		t.Fatal("total observed output bytes must not be confused with the retained-prefix limit")
	}
	assertSchemaNumber(t, outputProperties, "retained_bytes", "maximum", MaxOutputBytes)

	manifest := objectValue(t, definitions["artifact_manifest"])
	assertStrictSchemaObject(t, "artifact manifest", manifest)
	assertSchemaRootNumber(t, manifest, "x-awg-max-total-file-bytes", MaxTotalArtifactBytes)
	manifestProperties := objectValue(t, manifest["properties"])
	assertSchemaEnum(t, objectValue(t, manifestProperties["status"]), []string{
		string(ArtifactStatusComplete), string(ArtifactStatusCompleteWithOmissions),
		string(ArtifactStatusFailed), string(ArtifactStatusNotRequested),
	})
	assertArrayLimit(t, manifestProperties, "files", MaxArtifactFiles)
	assertArrayLimit(t, manifestProperties, "omissions", MaxArtifactOmissions)

	artifactFile := objectValue(t, definitions["artifact_file"])
	assertStrictSchemaObject(t, "artifact file", artifactFile)
	artifactFileProperties := objectValue(t, artifactFile["properties"])
	assertSchemaNumber(t, artifactFileProperties, "path", "x-awg-max-utf8-bytes", MaxArtifactFilePathBytes)
	assertSchemaNumber(t, artifactFileProperties, "size_bytes", "maximum", MaxArtifactFileBytes)

	omission := objectValue(t, definitions["artifact_omission"])
	assertStrictSchemaObject(t, "artifact omission", omission)
	omissionProperties := objectValue(t, omission["properties"])
	assertSchemaNumber(t, omissionProperties, "pattern", "x-awg-max-utf8-bytes", MaxArtifactPathBytes)
	assertSchemaEnum(t, objectValue(t, omissionProperties["reason"]), []string{
		string(ArtifactOmissionByteLimit), string(ArtifactOmissionCollectionFailed),
		string(ArtifactOmissionFileLimit), string(ArtifactOmissionLinkRejected),
		string(ArtifactOmissionNoMatch), string(ArtifactOmissionPolicyRejected),
		string(ArtifactOmissionReadFailed), string(ArtifactOmissionUnsupportedType),
	})
	assertStrictSchemaObject(t, "result workflow provenance", objectValue(t, definitions["workflow_provenance"]))

	conditionals, ok := schema["allOf"].([]any)
	if !ok || len(conditionals) != 3 {
		t.Fatalf("result schema must encode three command/exit correlations: %#v", schema["allOf"])
	}
}

func TestExecutionReportSchemaIsStrictAndExcludesFinalizerAuthority(t *testing.T) {
	schema := parseSchema(t, "execution-report.schema.json")
	assertStrictSchemaObject(t, "execution report", schema)
	assertSchemaRootNumber(t, schema, "x-awg-max-encoded-bytes", MaxExecutionReportBytes)
	assertRequiredFields(t, schema, []string{
		"artifacts", "attempt_id", "command_status", "duration_ms", "exit_code", "finished_at",
		"gateway_source_sha", "protocol_version", "request_digest", "request_id", "started_at", "stderr", "stdout",
	})
	properties := objectValue(t, schema["properties"])
	if _, present := properties["finalized_at"]; present {
		t.Fatal("execution report schema grants finalization timestamp authority")
	}
	if _, present := properties["workflow"]; present {
		t.Fatal("execution report schema grants workflow provenance authority")
	}
	conditionals, ok := schema["allOf"].([]any)
	if !ok || len(conditionals) != 3 {
		t.Fatalf("execution report schema must encode three command/exit correlations: %#v", schema["allOf"])
	}
}

func TestLedgerExamplesDecodeRoundTripAndBind(t *testing.T) {
	request, err := DecodeRequest(readProtocolFile(t, "examples", "v1", "request.json"))
	if err != nil {
		t.Fatalf("request example is invalid: %v", err)
	}
	accepted, err := DecodeAcceptedRequestRecord(readProtocolFile(t, "examples", "v1", "accepted-request.json"))
	if err != nil {
		t.Fatalf("accepted request example is invalid: %v", err)
	}
	if !reflect.DeepEqual(accepted.Request, request) {
		t.Fatal("accepted request example does not embed the request example")
	}
	digest, err := DigestRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.RequestDigest != digest {
		t.Fatalf("accepted example digest %q does not match request digest %q", accepted.RequestDigest, digest)
	}

	result, err := DecodeResultRecord(readProtocolFile(t, "examples", "v1", "result.json"))
	if err != nil {
		t.Fatalf("result example is invalid: %v", err)
	}
	if err := ValidateResultBinding(accepted, result); err != nil {
		t.Fatalf("result example does not bind to accepted example: %v", err)
	}
	report, err := DecodeExecutionReport(readProtocolFile(t, "examples", "v1", "execution-report.json"))
	if err != nil {
		t.Fatalf("execution report example is invalid: %v", err)
	}
	if err := ValidateExecutionReportBinding(accepted, report); err != nil {
		t.Fatalf("execution report example does not bind to accepted example: %v", err)
	}
	if !reflect.DeepEqual(report, executionReportFromResult(result)) {
		t.Fatal("execution report example does not match the non-authoritative fields of the result example")
	}
	assertCanonicalRecordRoundTrip(t, accepted, result)
}

func TestRequestSchemaDeclaresEncodedLimit(t *testing.T) {
	schema := parseSchema(t, "request.schema.json")
	assertSchemaRootNumber(t, schema, "x-awg-max-encoded-bytes", MaxRequestBytes)
}

func parseSchema(t *testing.T, name string) map[string]any {
	t.Helper()
	content := readProtocolFile(t, "schemas", "v1", name)
	var schema map[string]any
	if err := json.Unmarshal(content, &schema); err != nil {
		t.Fatalf("invalid %s JSON: %v", name, err)
	}
	return schema
}

func assertCanonicalRecordRoundTrip(t *testing.T, accepted AcceptedRequestRecord, result ResultRecord) {
	t.Helper()
	canonicalAccepted, err := MarshalCanonicalAcceptedRequestRecord(accepted)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAcceptedRequestRecord(canonicalAccepted); err != nil {
		t.Fatalf("canonical accepted record did not round trip: %v", err)
	}
	canonicalResult, err := MarshalCanonicalResultRecord(result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeResultRecord(canonicalResult); err != nil {
		t.Fatalf("canonical result record did not round trip: %v", err)
	}
}

func assertStrictSchemaObject(t *testing.T, name string, schema map[string]any) {
	t.Helper()
	if schema["type"] != "object" || schema["additionalProperties"] != false {
		t.Fatalf("%s schema is not a strict object: %#v", name, schema)
	}
}

func assertRequiredFields(t *testing.T, schema map[string]any, expected []string) {
	t.Helper()
	actual := stringSlice(t, schema["required"])
	sort.Strings(actual)
	sort.Strings(expected)
	if !equalStrings(actual, expected) {
		t.Fatalf("unexpected required fields: %#v", actual)
	}
}

func assertSchemaRootNumber(t *testing.T, schema map[string]any, field string, expected int) {
	t.Helper()
	if schema[field] != float64(expected) {
		t.Fatalf("schema %s mismatch: %#v", field, schema[field])
	}
}

func assertSchemaEnum(t *testing.T, schema map[string]any, expected []string) {
	t.Helper()
	actual := stringSlice(t, schema["enum"])
	sort.Strings(actual)
	sort.Strings(expected)
	if !equalStrings(actual, expected) {
		t.Fatalf("schema enum mismatch: %#v", actual)
	}
}

func assertArrayLimit(t *testing.T, properties map[string]any, name string, expected int) {
	t.Helper()
	property := objectValue(t, properties[name])
	if property["maxItems"] != float64(expected) {
		t.Fatalf("schema %s maxItems mismatch: %#v", name, property["maxItems"])
	}
}
