package installconfig

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestConfigCanonicalRoundTrip(t *testing.T) {
	for _, configuration := range []Config{validWindowsConfig(), validLinuxConfig()} {
		encoded, err := MarshalCanonical(configuration)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := Decode(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.ExecutionIdentity.Identifier != configuration.ExecutionIdentity.Identifier || decoded.Platform != configuration.Platform {
			t.Fatalf("configuration changed: %#v", decoded)
		}
	}
}

func TestConfigDecodeIsStrictAndDoesNotEchoUnknownFields(t *testing.T) {
	encoded := mustEncodeConfig(t, validWindowsConfig())
	marker := "SYNTHETIC-MANAGEMENT-FIELD-4242"
	tests := []struct {
		name string
		body []byte
		rule string
	}{
		{name: "unknown run as", body: []byte(strings.Replace(string(encoded), `"capabilities":`, `"`+marker+`":"administrator","capabilities":`, 1)), rule: "json-unknown-field"},
		{name: "case variant", body: []byte(strings.Replace(string(encoded), `"platform":`, `"Platform":`, 1)), rule: "json-unknown-field"},
		{name: "missing array", body: []byte(strings.Replace(string(encoded), `,"capabilities":[]`, "", 1)), rule: "json-missing-required-field"},
		{name: "duplicate", body: []byte(strings.Replace(string(encoded), `"platform":"windows"`, `"platform":"windows","platform":"linux"`, 1)), rule: "json-duplicate-object-key"},
		{name: "trailing", body: append(encoded, []byte(" {}")...), rule: "json-trailing-json"},
		{name: "invalid utf8", body: []byte{'{', '"', 0xff, '"', ':', '1', '}'}, rule: "json-invalid-utf8"},
		{name: "oversized", body: []byte(strings.Repeat(" ", MaxConfigBytes+1)), rule: "json-record-too-large"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Decode(test.body)
			assertConfigError(t, err, "config", test.rule)
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("configuration error echoed unknown field: %q", err)
			}
		})
	}
}

func mustEncodeConfig(t *testing.T, configuration Config) []byte {
	t.Helper()
	encoded, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func assertConfigError(t *testing.T, err error, field string, rule string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected config error %s/%s", field, rule)
	}
	var validationFailure *Error
	if !errors.As(err, &validationFailure) {
		t.Fatalf("expected config error, got %T: %v", err, err)
	}
	if validationFailure.Field != field || validationFailure.Rule != rule {
		t.Fatalf("expected %s/%s, got %s/%s", field, rule, validationFailure.Field, validationFailure.Rule)
	}
}
