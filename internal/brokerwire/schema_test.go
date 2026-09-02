package brokerwire

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPreambleSchemaIsStrictAndMatchesContract(t *testing.T) {
	schema := readJSONObject(t, filepath.Join("..", "..", "runtime", "schemas", "v1", "broker-response-preamble.schema.json"))
	if schema["additionalProperties"] != false {
		t.Fatal("broker response preamble schema must reject unknown fields")
	}
	if schema["x-awg-max-encoded-bytes"] != float64(MaxPreambleBytes) {
		t.Fatal("broker response preamble schema byte limit drifted")
	}
	required := stringArray(t, schema["required"])
	want := []string{
		"protocol_version", "outcome", "failure", "stdout_retained_sha256", "stderr_retained_sha256",
	}
	if !reflect.DeepEqual(required, want) {
		t.Fatalf("schema required fields drifted: %v", required)
	}
	properties := object(t, schema["properties"])
	if len(properties) != len(want) {
		t.Fatalf("schema property set drifted: %v", properties)
	}
	for _, name := range want {
		if _, found := properties[name]; !found {
			t.Fatalf("schema property %q is missing", name)
		}
	}
}

func TestPreambleExampleMatchesCanonicalContract(t *testing.T) {
	path := filepath.Join("..", "..", "runtime", "examples", "v1", "broker-response-preamble.json")
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	preamble, err := DecodePreamble(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if preamble.Outcome != OutcomeExecution || preamble.Failure != FailureNone {
		t.Fatalf("unexpected preamble example: %#v", preamble)
	}
	canonical, err := MarshalCanonicalPreamble(preamble)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePreamble(canonical)
	if err != nil || decoded != preamble {
		t.Fatalf("canonical preamble changed: %#v / %v", decoded, err)
	}
}

func readJSONObject(t *testing.T, path string) map[string]any {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func object(t *testing.T, value any) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("expected object, got %T", value)
	}
	return object
}

func stringArray(t *testing.T, value any) []string {
	t.Helper()
	items, ok := value.([]any)
	if !ok {
		t.Fatalf("expected array, got %T", value)
	}
	result := make([]string, len(items))
	for index, item := range items {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("expected string item, got %T", item)
		}
		result[index] = text
	}
	return result
}
