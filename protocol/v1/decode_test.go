package v1

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeRequestRejectsInvalidJSONBoundaries(t *testing.T) {
	validJSON := mustEncodeRequest(t, validRequest())
	tests := []struct {
		name string
		body []byte
		rule string
	}{
		{name: "empty", body: []byte(" \r\n"), rule: "empty-json"},
		{name: "root array", body: []byte("[]"), rule: "root-not-object"},
		{name: "malformed", body: []byte(`{"protocol_version":`), rule: "malformed-json"},
		{name: "invalid utf8", body: []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}, rule: "invalid-utf8"},
		{name: "trailing value", body: append(append([]byte{}, validJSON...), []byte(" {}")...), rule: "trailing-json"},
		{name: "oversized", body: []byte(`{"padding":"` + strings.Repeat("x", MaxRequestBytes) + `"}`), rule: "record-too-large"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeRequest(test.body)
			assertProtocolError(t, err, ErrorKindDecode, "request", test.rule)
		})
	}
}

func TestDecodeRequestRejectsUnknownAndDuplicateFieldsWithoutEchoingValues(t *testing.T) {
	privateMarker := "SYNTHETIC-PRIVATE-MARKER-4242"
	unknown := strings.Replace(string(mustEncodeRequest(t, validRequest())), `"artifacts":[]`, `"artifacts":[],"`+privateMarker+`":true`, 1)
	_, err := DecodeRequest([]byte(unknown))
	assertProtocolError(t, err, ErrorKindDecode, "request", "schema-decode")
	if strings.Contains(err.Error(), privateMarker) {
		t.Fatalf("decode error echoed an unknown private field: %q", err)
	}

	duplicateRoot := strings.Replace(string(mustEncodeRequest(t, validRequest())), `"request_id":"req-000001"`, `"request_id":"req-000001","request_id":"req-000002"`, 1)
	_, err = DecodeRequest([]byte(duplicateRoot))
	assertProtocolError(t, err, ErrorKindDecode, "request", "duplicate-object-key")

	request := validRequest()
	request.Artifacts = []ArtifactSelection{{Name: "results", Paths: []string{"one.txt"}}}
	duplicateNested := strings.Replace(string(mustEncodeRequest(t, request)), `"name":"results"`, `"name":"results","name":"other"`, 1)
	_, err = DecodeRequest([]byte(duplicateNested))
	assertProtocolError(t, err, ErrorKindDecode, "request", "duplicate-object-key")
}

func TestCanonicalRequestDigestIgnoresJSONFormattingAndPropertyOrder(t *testing.T) {
	one := []byte(`{
  "protocol_version": 1,
  "request_id": "req-000001",
  "session_id": "example-session",
  "actor": "codex",
  "operation": "execute",
  "process_id": "",
  "shell": "pwsh",
  "working_directory": "C:\\Users\\Alice\\Projects\\demo",
  "script": "Get-ChildItem\n",
  "timeout_seconds": 900,
  "max_output_bytes": 1048576,
  "artifacts": []
}`)
	two := []byte(`{"artifacts":[],"max_output_bytes":1048576,"timeout_seconds":900,"script":"Get-ChildItem\n","working_directory":"C:\\Users\\Alice\\Projects\\demo","shell":"pwsh","process_id":"","operation":"execute","actor":"codex","session_id":"example-session","request_id":"req-000001","protocol_version":1}`)

	requestOne, err := DecodeRequest(one)
	if err != nil {
		t.Fatal(err)
	}
	requestTwo, err := DecodeRequest(two)
	if err != nil {
		t.Fatal(err)
	}
	digestOne, err := DigestRequest(requestOne)
	if err != nil {
		t.Fatal(err)
	}
	digestTwo, err := DigestRequest(requestTwo)
	if err != nil {
		t.Fatal(err)
	}
	if digestOne != digestTwo || len(digestOne) != 64 {
		t.Fatalf("canonical digests differ: %q != %q", digestOne, digestTwo)
	}

	canonical, err := MarshalCanonicalRequest(requestOne)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := DecodeRequest(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if roundTrip.RequestID != requestOne.RequestID || roundTrip.WorkingDirectory != requestOne.WorkingDirectory {
		t.Fatalf("canonical round trip changed request: %#v", roundTrip)
	}
}

func mustEncodeRequest(t *testing.T, request Request) []byte {
	t.Helper()
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
