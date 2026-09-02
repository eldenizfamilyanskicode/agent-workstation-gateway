package v1

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateRequestAcceptsSupportedShellsAndPaths(t *testing.T) {
	shells := []Shell{ShellBash, ShellCmd, ShellGitBash, ShellPowerShell, ShellPwsh}
	workingDirectories := []string{
		`C:\Users\Alice\Projects\demo`,
		`c:\projects`,
		`D:\`,
		`/home/alice/projects/demo`,
		`/`,
	}
	for _, shell := range shells {
		for _, workingDirectory := range workingDirectories {
			request := validRequest()
			request.Shell = shell
			request.WorkingDirectory = workingDirectory
			if err := ValidateRequest(request); err != nil {
				t.Fatalf("shell %q path %q rejected: %v", shell, workingDirectory, err)
			}
		}
	}
}

func TestValidateRequestRejectsInvalidFields(t *testing.T) {
	tests := []struct {
		name  string
		alter func(*Request)
		field string
		rule  string
	}{
		{name: "version", alter: func(request *Request) { request.ProtocolVersion = 2 }, field: "protocol_version", rule: "unsupported-version"},
		{name: "request id", alter: func(request *Request) { request.RequestID = "UPPER" }, field: "request_id", rule: "invalid-identifier"},
		{name: "session id", alter: func(request *Request) { request.SessionID = "" }, field: "session_id", rule: "invalid-identifier"},
		{name: "actor", alter: func(request *Request) { request.Actor = strings.Repeat("a", MaxIdentifierBytes+1) }, field: "actor", rule: "invalid-identifier"},
		{name: "shell", alter: func(request *Request) { request.Shell = "zsh" }, field: "shell", rule: "unsupported-shell"},
		{name: "empty script", alter: func(request *Request) { request.Script = " \n\t" }, field: "script", rule: "empty-script"},
		{name: "nul script", alter: func(request *Request) { request.Script = "echo\x00value" }, field: "script", rule: "contains-nul"},
		{name: "large script", alter: func(request *Request) { request.Script = strings.Repeat("x", MaxScriptBytes+1) }, field: "script", rule: "outside-size-limit"},
		{name: "short timeout", alter: func(request *Request) { request.TimeoutSeconds = MinTimeoutSeconds - 1 }, field: "timeout_seconds", rule: "outside-allowed-range"},
		{name: "long timeout", alter: func(request *Request) { request.TimeoutSeconds = MaxTimeoutSeconds + 1 }, field: "timeout_seconds", rule: "outside-allowed-range"},
		{name: "small output", alter: func(request *Request) { request.MaxOutputBytes = MinOutputBytes - 1 }, field: "max_output_bytes", rule: "outside-allowed-range"},
		{name: "large output", alter: func(request *Request) { request.MaxOutputBytes = MaxOutputBytes + 1 }, field: "max_output_bytes", rule: "outside-allowed-range"},
		{name: "missing artifacts", alter: func(request *Request) { request.Artifacts = nil }, field: "artifacts", rule: "required-array"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validRequest()
			test.alter(&request)
			assertProtocolError(t, ValidateRequest(request), ErrorKindValidation, test.field, test.rule)
		})
	}
}

func TestValidateRequestRejectsUnsafeWorkingDirectories(t *testing.T) {
	tests := []struct {
		path string
		rule string
	}{
		{path: `relative\project`, rule: "not-supported-absolute-path"},
		{path: `\\server\share`, rule: "not-supported-absolute-path"},
		{path: `C:\Projects\..\private`, rule: "non-canonical-windows-segment"},
		{path: `C:\Projects\\demo`, rule: "non-canonical-windows-segment"},
		{path: `C:\Projects\CON.txt`, rule: "reserved-windows-name"},
		{path: `C:\Projects\demo.`, rule: "ambiguous-windows-segment"},
		{path: `C:/Projects/demo`, rule: "not-supported-absolute-path"},
		{path: `/home/alice/../private`, rule: "non-canonical-posix-segment"},
		{path: `/home//demo`, rule: "non-canonical-posix-segment"},
		{path: `/home/alice\demo`, rule: "ambiguous-posix-separator"},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			request := validRequest()
			request.WorkingDirectory = test.path
			assertProtocolError(t, ValidateRequest(request), ErrorKindValidation, "working_directory", test.rule)
		})
	}
}

func TestValidateRequestArtifactBoundaries(t *testing.T) {
	validPaths := []string{
		"test-results/**/*.png",
		"reports/result-?.json",
		"logs/[ab].log",
	}
	request := validRequest()
	request.Artifacts = []ArtifactSelection{{Name: "test-results", Paths: validPaths}}
	if err := ValidateRequest(request); err != nil {
		t.Fatalf("valid artifact paths rejected: %v", err)
	}

	invalidPaths := []struct {
		path string
		rule string
	}{
		{path: "/absolute.txt", rule: "not-safe-relative-path"},
		{path: `C:\secret.txt`, rule: "not-safe-relative-path"},
		{path: "../secret.txt", rule: "non-canonical-segment"},
		{path: "reports//result.json", rule: "non-canonical-segment"},
		{path: "reports/[bad.json", rule: "invalid-glob-syntax"},
		{path: ".git/config", rule: "sensitive-segment"},
		{path: ".env.production", rule: "sensitive-segment"},
	}
	for _, test := range invalidPaths {
		t.Run(test.path, func(t *testing.T) {
			request := validRequest()
			request.Artifacts = []ArtifactSelection{{Name: "results", Paths: []string{test.path}}}
			assertProtocolError(t, ValidateRequest(request), ErrorKindValidation, "artifacts.paths", test.rule)
		})
	}
}

func TestValidateRequestRejectsDuplicateAndExcessiveArtifactSelections(t *testing.T) {
	tests := []struct {
		name      string
		artifacts []ArtifactSelection
		field     string
		rule      string
	}{
		{
			name: "duplicate group",
			artifacts: []ArtifactSelection{
				{Name: "results", Paths: []string{"one.txt"}},
				{Name: "results", Paths: []string{"two.txt"}},
			},
			field: "artifacts.name",
			rule:  "duplicate-group",
		},
		{
			name:      "duplicate path",
			artifacts: []ArtifactSelection{{Name: "results", Paths: []string{"one.txt", "one.txt"}}},
			field:     "artifacts.paths",
			rule:      "duplicate-path",
		},
		{
			name:      "empty paths",
			artifacts: []ArtifactSelection{{Name: "results", Paths: []string{}}},
			field:     "artifacts.paths",
			rule:      "outside-count-limit",
		},
		{
			name:      "invalid group",
			artifacts: []ArtifactSelection{{Name: "UPPER", Paths: []string{"one.txt"}}},
			field:     "artifacts.name",
			rule:      "invalid-identifier",
		},
		{
			name:      "too many paths",
			artifacts: []ArtifactSelection{{Name: "results", Paths: numberedArtifactPaths(MaxArtifactPaths + 1)}},
			field:     "artifacts.paths",
			rule:      "outside-count-limit",
		},
		{
			name:      "too many groups",
			artifacts: numberedArtifactGroups(MaxArtifactGroups+1, 1),
			field:     "artifacts",
			rule:      "too-many-groups",
		},
		{
			name:      "too many total paths",
			artifacts: numberedArtifactGroups(MaxArtifactGroups, MaxArtifactPaths),
			field:     "artifacts.paths",
			rule:      "too-many-total-paths",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validRequest()
			request.Artifacts = test.artifacts
			assertProtocolError(t, ValidateRequest(request), ErrorKindValidation, test.field, test.rule)
		})
	}
}

func TestValidateRequestAcceptsExactNumericAndScriptLimits(t *testing.T) {
	requests := []Request{validRequest(), validRequest()}
	requests[0].TimeoutSeconds = MinTimeoutSeconds
	requests[0].MaxOutputBytes = MinOutputBytes
	requests[1].TimeoutSeconds = MaxTimeoutSeconds
	requests[1].MaxOutputBytes = MaxOutputBytes
	requests[1].Script = strings.Repeat("x", MaxScriptBytes)
	for index, request := range requests {
		if err := ValidateRequest(request); err != nil {
			t.Fatalf("boundary request %d rejected: %v", index, err)
		}
	}
}

func TestMarshalCanonicalRequestEnforcesEncodedRequestLimit(t *testing.T) {
	request := validRequest()
	request.Script = strings.Repeat("x", MaxScriptBytes)
	request.Artifacts = numberedArtifactGroups(MaxArtifactGroups, MaxTotalArtifactPaths/MaxArtifactGroups)
	longPrefix := strings.Repeat("a", MaxArtifactPathBytes-16)
	for groupIndex := range request.Artifacts {
		for pathIndex := range request.Artifacts[groupIndex].Paths {
			request.Artifacts[groupIndex].Paths[pathIndex] = longPrefix + "-" + string(rune('a'+groupIndex)) + "-" + string(rune('a'+pathIndex)) + ".txt"
		}
	}
	_, err := MarshalCanonicalRequest(request)
	assertProtocolError(t, err, ErrorKindValidation, "request", "canonical-size-limit")
}

func validRequest() Request {
	return Request{
		ProtocolVersion:  Version,
		RequestID:        "req-000001",
		SessionID:        "example-session",
		Actor:            "codex",
		Shell:            ShellPwsh,
		WorkingDirectory: `C:\Users\Alice\Projects\demo`,
		Script:           "Get-ChildItem\n",
		TimeoutSeconds:   900,
		MaxOutputBytes:   1024 * 1024,
		Artifacts:        []ArtifactSelection{},
	}
}

func numberedArtifactGroups(groupCount int, pathCount int) []ArtifactSelection {
	artifacts := make([]ArtifactSelection, 0, groupCount)
	for groupIndex := 0; groupIndex < groupCount; groupIndex++ {
		artifacts = append(artifacts, ArtifactSelection{
			Name:  "group-" + string(rune('a'+groupIndex)),
			Paths: numberedArtifactPaths(pathCount),
		})
	}
	return artifacts
}

func numberedArtifactPaths(count int) []string {
	paths := make([]string, 0, count)
	for index := 0; index < count; index++ {
		paths = append(paths, "result-"+string(rune('a'+index))+".txt")
	}
	return paths
}

func assertProtocolError(t *testing.T, err error, kind ErrorKind, field string, rule string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s/%s/%s error", kind, field, rule)
	}
	var protocolError *ProtocolError
	if !errors.As(err, &protocolError) {
		t.Fatalf("expected ProtocolError, got %T: %v", err, err)
	}
	if protocolError.Kind != kind || protocolError.Field != field || protocolError.Rule != rule {
		t.Fatalf("unexpected error: %#v", protocolError)
	}
}
