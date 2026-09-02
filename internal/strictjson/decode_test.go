package strictjson

import (
	"errors"
	"strings"
	"testing"
)

type testEnvelope struct {
	Name    string       `json:"name"`
	Enabled bool         `json:"enabled"`
	Nested  testNested   `json:"nested"`
	Items   []testNested `json:"items"`
	Code    *int         `json:"code"`
}

type testNested struct {
	Count int `json:"count"`
}

func TestDecodeObjectAcceptsExactRequiredFields(t *testing.T) {
	encoded := []byte(`{"name":"example","enabled":false,"nested":{"count":0},"items":[{"count":1}],"code":null}`)
	var decoded testEnvelope
	if err := DecodeObject(encoded, 1024, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Name != "example" || decoded.Enabled || decoded.Nested.Count != 0 || decoded.Code != nil {
		t.Fatalf("unexpected decoded value: %#v", decoded)
	}
}

func TestDecodeObjectRejectsBoundaryViolations(t *testing.T) {
	valid := `{"name":"example","enabled":false,"nested":{"count":0},"items":[],"code":null}`
	tests := []struct {
		name string
		body []byte
		rule string
	}{
		{name: "empty", body: nil, rule: "empty-json"},
		{name: "oversized", body: []byte(strings.Repeat(" ", 1025)), rule: "record-too-large"},
		{name: "invalid utf8", body: []byte{'{', '"', 0xff, '"', ':', '1', '}'}, rule: "invalid-utf8"},
		{name: "root", body: []byte(`[]`), rule: "root-not-object"},
		{name: "malformed", body: []byte(`{"name":`), rule: "malformed-json"},
		{name: "trailing", body: []byte(valid + ` {}`), rule: "trailing-json"},
		{name: "duplicate", body: []byte(strings.Replace(valid, `"name":"example"`, `"name":"example","name":"other"`, 1)), rule: "duplicate-object-key"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var decoded testEnvelope
			assertRule(t, DecodeObject(test.body, 1024, &decoded), test.rule)
		})
	}
}

func TestDecodeObjectRequiresExactNestedFields(t *testing.T) {
	marker := "SYNTHETIC-UNKNOWN-FIELD-4242"
	tests := []struct {
		name string
		body string
		rule string
	}{
		{name: "unknown", body: `{"name":"example","enabled":false,"nested":{"count":0},"items":[],"code":null,"` + marker + `":true}`, rule: "unknown-field"},
		{name: "case variant", body: `{"Name":"example","enabled":false,"nested":{"count":0},"items":[],"code":null}`, rule: "unknown-field"},
		{name: "missing false", body: `{"name":"example","nested":{"count":0},"items":[],"code":null}`, rule: "missing-required-field"},
		{name: "nested missing zero", body: `{"name":"example","enabled":false,"nested":{},"items":[],"code":null}`, rule: "missing-required-field"},
		{name: "array item unknown", body: `{"name":"example","enabled":false,"nested":{"count":0},"items":[{"count":1,"other":2}],"code":null}`, rule: "unknown-field"},
		{name: "scalar null", body: `{"name":"example","enabled":null,"nested":{"count":0},"items":[],"code":null}`, rule: "schema-decode"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var decoded testEnvelope
			err := DecodeObject([]byte(test.body), 1024, &decoded)
			assertRule(t, err, test.rule)
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("decode error echoed unknown field: %q", err)
			}
		})
	}
}

func assertRule(t *testing.T, err error, expected string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected strict JSON error %q", expected)
	}
	var decodeFailure *Error
	if !errors.As(err, &decodeFailure) {
		t.Fatalf("expected strict JSON error, got %T: %v", err, err)
	}
	if decodeFailure.Rule != expected {
		t.Fatalf("expected rule %q, got %q", expected, decodeFailure.Rule)
	}
}
