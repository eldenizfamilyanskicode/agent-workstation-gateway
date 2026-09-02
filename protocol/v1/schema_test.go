package v1

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
)

func TestRequestSchemaIsStrictAndMatchesContract(t *testing.T) {
	schemaBytes := readProtocolFile(t, "schemas", "v1", "request.schema.json")
	var schema map[string]any
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		t.Fatalf("invalid request schema JSON: %v", err)
	}
	if schema["type"] != "object" || schema["additionalProperties"] != false {
		t.Fatalf("request schema root is not a strict object: %#v", schema)
	}

	required := stringSlice(t, schema["required"])
	sort.Strings(required)
	expectedRequired := []string{
		"actor", "artifacts", "max_output_bytes", "protocol_version", "request_id",
		"script", "session_id", "shell", "timeout_seconds", "working_directory",
	}
	if !equalStrings(required, expectedRequired) {
		t.Fatalf("unexpected required fields: %#v", required)
	}

	properties := objectValue(t, schema["properties"])
	protocolVersion := objectValue(t, properties["protocol_version"])
	if protocolVersion["const"] != float64(Version) {
		t.Fatalf("schema version mismatch: %#v", protocolVersion["const"])
	}
	shell := objectValue(t, properties["shell"])
	actualShells := stringSlice(t, shell["enum"])
	expectedShells := []string{string(ShellBash), string(ShellCmd), string(ShellGitBash), string(ShellPowerShell), string(ShellPwsh)}
	if !equalStrings(actualShells, expectedShells) {
		t.Fatalf("schema shell enum mismatch: %#v", actualShells)
	}
	assertSchemaNumber(t, properties, "timeout_seconds", "minimum", MinTimeoutSeconds)
	assertSchemaNumber(t, properties, "timeout_seconds", "maximum", MaxTimeoutSeconds)
	assertSchemaNumber(t, properties, "max_output_bytes", "minimum", MinOutputBytes)
	assertSchemaNumber(t, properties, "max_output_bytes", "maximum", MaxOutputBytes)
	assertSchemaNumber(t, properties, "working_directory", "x-awg-max-utf8-bytes", MaxWorkingPathBytes)
	assertSchemaNumber(t, properties, "script", "x-awg-max-utf8-bytes", MaxScriptBytes)

	definitions := objectValue(t, schema["$defs"])
	artifactSelection := objectValue(t, definitions["artifact_selection"])
	if artifactSelection["additionalProperties"] != false {
		t.Fatal("artifact selection schema permits unknown fields")
	}
	artifactProperties := objectValue(t, artifactSelection["properties"])
	artifactPaths := objectValue(t, artifactProperties["paths"])
	if artifactPaths["maxItems"] != float64(MaxArtifactPaths) {
		t.Fatalf("artifact path count mismatch: %#v", artifactPaths["maxItems"])
	}
	artifactPath := objectValue(t, artifactPaths["items"])
	if artifactPath["x-awg-max-utf8-bytes"] != float64(MaxArtifactPathBytes) {
		t.Fatalf("artifact path byte limit mismatch: %#v", artifactPath["x-awg-max-utf8-bytes"])
	}
}

func TestRequestExampleDecodesAndRoundTrips(t *testing.T) {
	exampleBytes := readProtocolFile(t, "examples", "v1", "request.json")
	request, err := DecodeRequest(exampleBytes)
	if err != nil {
		t.Fatalf("request example is invalid: %v", err)
	}
	canonical, err := MarshalCanonicalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(canonical) {
		t.Fatal("canonical request is not JSON")
	}
	if _, err := DecodeRequest(canonical); err != nil {
		t.Fatalf("canonical request did not round trip: %v", err)
	}
}

func readProtocolFile(t *testing.T, pathParts ...string) []byte {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve protocol test source")
	}
	parts := append([]string{filepath.Dir(sourceFile), ".."}, pathParts...)
	filePath := filepath.Join(parts...)
	content, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func objectValue(t *testing.T, value any) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("expected object, got %T", value)
	}
	return object
}

func stringSlice(t *testing.T, value any) []string {
	t.Helper()
	values, ok := value.([]any)
	if !ok {
		t.Fatalf("expected array, got %T", value)
	}
	result := make([]string, 0, len(values))
	for _, item := range values {
		stringItem, ok := item.(string)
		if !ok {
			t.Fatalf("expected string array item, got %T", item)
		}
		result = append(result, stringItem)
	}
	return result
}

func assertSchemaNumber(t *testing.T, properties map[string]any, propertyName string, constraint string, expected int) {
	t.Helper()
	property := objectValue(t, properties[propertyName])
	if property[constraint] != float64(expected) {
		t.Fatalf("schema %s.%s mismatch: %#v", propertyName, constraint, property[constraint])
	}
}

func equalStrings(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
