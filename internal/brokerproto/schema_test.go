package brokerproto

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"testing"

	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

func TestExecuteEnvelopeSchemaIsStrictAndMatchesContract(t *testing.T) {
	schema := brokerSchemaObject(t, brokerRepositoryFile(t, "runtime", "schemas", "v1", "execute-envelope.schema.json"))
	if schema["type"] != "object" || schema["additionalProperties"] != false {
		t.Fatalf("execute envelope schema root is not strict: %#v", schema)
	}
	if schema["x-awg-max-encoded-bytes"] != float64(MaxExecuteEnvelopeBytes) {
		t.Fatal("execute envelope schema limit differs from Go contract")
	}
	required := brokerStringArray(t, schema["required"])
	sort.Strings(required)
	expected := []string{"accepted_request", "attempt_id", "operation", "protocol_version"}
	if !reflect.DeepEqual(required, expected) {
		t.Fatalf("execute envelope required fields differ: %#v", required)
	}
	properties := brokerObject(t, schema["properties"])
	operation := brokerObject(t, properties["operation"])
	if operation["const"] != string(OperationExecute) {
		t.Fatal("execute envelope operation differs from Go contract")
	}
	accepted := brokerObject(t, properties["accepted_request"])
	if accepted["$ref"] != "../../../protocol/schemas/v1/accepted-request.schema.json" {
		t.Fatal("execute envelope schema does not bind the accepted-request schema")
	}
	attempt := brokerObject(t, properties["attempt_id"])
	if attempt["maxLength"] != float64(64) {
		t.Fatal("execute envelope attempt limit differs from Go contract")
	}
}

func TestExecuteEnvelopeExampleMatchesAcceptedExample(t *testing.T) {
	executeBytes, err := os.ReadFile(brokerRepositoryFile(t, "runtime", "examples", "v1", "execute-envelope.json"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := DecodeExecuteEnvelope(executeBytes)
	if err != nil {
		t.Fatalf("execute envelope example rejected: %v", err)
	}
	acceptedBytes, err := os.ReadFile(brokerRepositoryFile(t, "protocol", "examples", "v1", "accepted-request.json"))
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := v1.DecodeAcceptedRequestRecord(acceptedBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(envelope.AcceptedRequest, accepted) {
		t.Fatal("execute envelope does not embed the accepted-request example")
	}
	canonical, err := MarshalCanonicalExecuteEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeExecuteEnvelope(canonical); err != nil {
		t.Fatalf("canonical execute envelope did not round trip: %v", err)
	}
}

func brokerRepositoryFile(t *testing.T, parts ...string) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve test source")
	}
	pathParts := append([]string{filepath.Dir(sourceFile), "..", ".."}, parts...)
	return filepath.Join(pathParts...)
}

func brokerSchemaObject(t *testing.T, path string) map[string]any {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("invalid execute envelope schema: %v", err)
	}
	return decoded
}

func brokerObject(t *testing.T, value any) map[string]any {
	t.Helper()
	decoded, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("expected object, got %T", value)
	}
	return decoded
}

func brokerStringArray(t *testing.T, value any) []string {
	t.Helper()
	items, ok := value.([]any)
	if !ok {
		t.Fatalf("expected array, got %T", value)
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		stringItem, ok := item.(string)
		if !ok {
			t.Fatalf("expected string, got %T", item)
		}
		result = append(result, stringItem)
	}
	return result
}
