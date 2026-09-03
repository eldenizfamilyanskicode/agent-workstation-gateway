package installplan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
)

func TestWindowsInstallSchemaIsStrictAndMatchesContract(t *testing.T) {
	schema := readSchemaObject(t, repositoryFile(t, "config", "schemas", "v1", "windows-install.schema.json"))
	if schema["type"] != "object" || schema["additionalProperties"] != false {
		t.Fatal("Windows install schema root is not strict")
	}
	if schema["x-awg-max-encoded-bytes"] != float64(MaxSpecBytes) {
		t.Fatal("Windows install schema byte limit differs from Go contract")
	}
	expected := []string{
		"approved_roots", "capabilities", "config_version", "control_account", "execution_account",
		"installation_root", "path_entries", "platform", "profile_root", "shells", "temp_root",
	}
	actual := schemaStrings(t, schema["required"])
	sort.Strings(actual)
	sort.Strings(expected)
	if len(actual) != len(expected) {
		t.Fatalf("required fields differ: %#v", actual)
	}
	for index := range actual {
		if actual[index] != expected[index] {
			t.Fatalf("required fields differ: %#v", actual)
		}
	}
	properties := schemaObject(t, schema["properties"])
	for _, forbidden := range []string{"control_sid", "execution_sid", "credential", "service_command"} {
		if _, exists := properties[forbidden]; exists {
			t.Fatalf("schema exposes forbidden authority field %q", forbidden)
		}
	}
}

func TestWindowsInstallExampleDecodesAndBuilds(t *testing.T) {
	encoded, err := os.ReadFile(repositoryFile(t, "config", "examples", "v1", "windows-install.json"))
	if err != nil {
		t.Fatal(err)
	}
	specification, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(specification.Capabilities) != 0 {
		t.Fatal("Windows install example enables an optional powerful capability")
	}
	if _, err := Build(specification); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxInstallSchemaAndExampleMatchContract(t *testing.T) {
	schema := readSchemaObject(t, repositoryFile(t, "config", "schemas", "v1", "linux-install.schema.json"))
	if schema["type"] != "object" || schema["additionalProperties"] != false ||
		schema["x-awg-max-encoded-bytes"] != float64(MaxSpecBytes) {
		t.Fatal("Linux install schema root differs from the strict contract")
	}
	encoded, err := os.ReadFile(repositoryFile(t, "config", "examples", "v1", "linux-install.json"))
	if err != nil {
		t.Fatal(err)
	}
	specification, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if specification.Platform != "linux" || len(specification.Capabilities) != 0 {
		t.Fatal("Linux example selected an invalid platform or powerful capability")
	}
	if _, err := Build(specification); err != nil {
		t.Fatal(err)
	}
}

func repositoryFile(t *testing.T, parts ...string) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve test source")
	}
	return filepath.Join(append([]string{filepath.Dir(sourceFile), "..", ".."}, parts...)...)
}

func readSchemaObject(t *testing.T, path string) map[string]any {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	return object
}

func schemaObject(t *testing.T, value any) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("expected object, got %T", value)
	}
	return object
}

func schemaStrings(t *testing.T, value any) []string {
	t.Helper()
	items, ok := value.([]any)
	if !ok {
		t.Fatalf("expected array, got %T", value)
	}
	result := make([]string, len(items))
	for index, item := range items {
		stringItem, ok := item.(string)
		if !ok {
			t.Fatalf("expected string, got %T", item)
		}
		result[index] = stringItem
	}
	return result
}
