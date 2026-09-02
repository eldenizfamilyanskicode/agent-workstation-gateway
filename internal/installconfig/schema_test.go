package installconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

func TestInstallationSchemaIsStrictAndMatchesLimits(t *testing.T) {
	schema := readObject(t, repositoryFile(t, "config", "schemas", "v1", "installation.schema.json"))
	if schema["type"] != "object" || schema["additionalProperties"] != false {
		t.Fatalf("installation schema root is not strict: %#v", schema)
	}
	if schema["x-awg-max-encoded-bytes"] != float64(MaxConfigBytes) {
		t.Fatal("installation schema encoded limit differs from Go contract")
	}
	assertRequired(t, schema, []string{
		"approved_roots", "capabilities", "config_version", "control_identity", "execution_identity",
		"path_entries", "platform", "profile_root", "shells", "temp_root",
	})

	properties := object(t, schema["properties"])
	assertArrayBounds(t, properties, "approved_roots", 1, maxApprovedRoots)
	assertArrayBounds(t, properties, "shells", 1, maxShells)
	assertArrayBounds(t, properties, "path_entries", 1, maxPathEntries)
	assertArrayBounds(t, properties, "capabilities", 0, maxCapabilities)
	capabilityItems := object(t, object(t, properties["capabilities"])["items"])
	capabilities := stringsFromArray(t, capabilityItems["enum"])
	if len(capabilities) != 1 || capabilities[0] != string(CapabilityDocker) {
		t.Fatalf("schema capability enum differs from Go contract: %#v", capabilities)
	}
	conditionals, ok := schema["allOf"].([]any)
	if !ok || len(conditionals) != 2 {
		t.Fatal("installation schema must have Windows and Linux conditionals")
	}
	definitions := object(t, schema["$defs"])
	for _, definitionName := range []string{"principal", "shell_binding"} {
		definition := object(t, definitions[definitionName])
		if definition["additionalProperties"] != false {
			t.Fatalf("%s schema permits unknown fields", definitionName)
		}
	}
	assertRequired(t, object(t, definitions["principal"]), []string{"identifier", "name", "primary_group_identifier"})
	assertRequired(t, object(t, definitions["shell_binding"]), []string{"executable", "shell"})
	absolutePath := object(t, definitions["absolute_path"])
	if absolutePath["x-awg-max-utf8-bytes"] != float64(platformpath.MaxPathBytes) {
		t.Fatal("installation schema path byte limit differs from Go contract")
	}
}

func TestInstallationExamplesDecodeAndUseSafeDefaults(t *testing.T) {
	tests := []struct {
		name     string
		platform string
	}{
		{name: "windows", platform: "windows"},
		{name: "linux", platform: "linux"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := os.ReadFile(repositoryFile(t, "config", "examples", "v1", test.name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			configuration, err := Decode(encoded)
			if err != nil {
				t.Fatalf("example rejected: %v", err)
			}
			if string(configuration.Platform) != test.platform || len(configuration.Capabilities) != 0 {
				t.Fatalf("example has unexpected platform/capabilities: %#v", configuration)
			}
			canonical, err := MarshalCanonical(configuration)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Decode(canonical); err != nil {
				t.Fatalf("canonical example did not round trip: %v", err)
			}
		})
	}
}

func repositoryFile(t *testing.T, parts ...string) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve test source")
	}
	pathParts := append([]string{filepath.Dir(sourceFile), "..", ".."}, parts...)
	return filepath.Join(pathParts...)
}

func readObject(t *testing.T, path string) map[string]any {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("invalid JSON schema: %v", err)
	}
	return decoded
}

func object(t *testing.T, value any) map[string]any {
	t.Helper()
	decoded, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("expected object, got %T", value)
	}
	return decoded
}

func stringsFromArray(t *testing.T, value any) []string {
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

func assertRequired(t *testing.T, schema map[string]any, expected []string) {
	t.Helper()
	actual := stringsFromArray(t, schema["required"])
	sort.Strings(actual)
	sort.Strings(expected)
	if len(actual) != len(expected) {
		t.Fatalf("required field count differs: %#v", actual)
	}
	for index := range actual {
		if actual[index] != expected[index] {
			t.Fatalf("required fields differ: %#v", actual)
		}
	}
}

func assertArrayBounds(t *testing.T, properties map[string]any, name string, minimum int, maximum int) {
	t.Helper()
	property := object(t, properties[name])
	if property["minItems"] != float64(minimum) || property["maxItems"] != float64(maximum) {
		t.Fatalf("schema bounds differ for %s: %#v", name, property)
	}
}
