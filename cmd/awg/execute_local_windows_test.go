//go:build windows

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/brokerwire"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/controlclient"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

func TestExecuteLocalPublishesWithoutEchoingSensitiveInput(t *testing.T) {
	directory := t.TempDir()
	acceptedPath := filepath.Join(directory, "accepted-private-marker.json")
	acceptedBytes, err := os.ReadFile(repositoryFile(t, "protocol", "examples", "v1", "accepted-request.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(acceptedPath, acceptedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(directory, "responses", "attempt-000001")
	if err := os.Mkdir(filepath.Dir(outputPath), 0o700); err != nil {
		t.Fatal(err)
	}

	previous := executeLocalExchange
	executeLocalExchange = func(
		_ context.Context,
		_ controlclient.Dialer,
		accepted v1.AcceptedRequestRecord,
		attemptID string,
		destination controlclient.Destination,
	) error {
		if attemptID != "attempt-000001" {
			t.Fatal("attempt identifier changed")
		}
		report := reportWithoutArtifactFiles(accepted, attemptID)
		return destination.Publish(brokerwire.Response{Report: report, Stdout: []byte{}, Stderr: []byte{}})
	}
	t.Cleanup(func() { executeLocalExchange = previous })

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run(context.Background(), []string{
		"execute-local", "--accepted", acceptedPath, "--attempt", "attempt-000001", "--output", outputPath,
	}, &stdout, &stderr)
	if exitCode != 0 || stdout.String() != "response published\n" || stderr.Len() != 0 {
		t.Fatalf("execute-local failed: exit=%d stdout=%q stderr=%q", exitCode, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(outputPath, "execution-report.json")); err != nil {
		t.Fatal("execute-local did not publish the response")
	}
	combined := stdout.String() + stderr.String()
	for _, forbidden := range []string{acceptedPath, outputPath, "Get-ChildItem", "alice/example-control"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("execute-local echoed sensitive input: %q", forbidden)
		}
	}
}

func TestExecuteLocalRejectsInvalidAndOversizedAcceptedRecordsWithoutEcho(t *testing.T) {
	directory := t.TempDir()
	tests := []struct {
		name    string
		content []byte
	}{
		{name: "invalid", content: []byte(`{"script":"SYNTHETIC-PRIVATE-MARKER"}`)},
		{name: "oversized", content: bytes.Repeat([]byte{'x'}, v1.MaxAcceptedRecordBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			acceptedPath := filepath.Join(directory, test.name+"-private.json")
			if err := os.WriteFile(acceptedPath, test.content, 0o600); err != nil {
				t.Fatal(err)
			}
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			exitCode := run(context.Background(), []string{
				"execute-local", "--accepted", acceptedPath, "--attempt", "attempt-1", "--output", filepath.Join(directory, "responses", test.name),
			}, &stdout, &stderr)
			if exitCode != 1 || stdout.Len() != 0 || strings.Contains(stderr.String(), acceptedPath) ||
				strings.Contains(stderr.String(), "SYNTHETIC-PRIVATE-MARKER") {
				t.Fatalf("unsafe rejection: exit=%d stdout=%q stderr=%q", exitCode, stdout.String(), stderr.String())
			}
		})
	}
}

func TestExecuteLocalRejectsMissingArgumentsWithoutMutation(t *testing.T) {
	directory := t.TempDir()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run(context.Background(), []string{"execute-local", "--accepted", filepath.Join(directory, "missing")}, &stdout, &stderr)
	if exitCode != 2 || stdout.Len() != 0 {
		t.Fatalf("missing arguments were accepted: exit=%d stdout=%q stderr=%q", exitCode, stdout.String(), stderr.String())
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("argument failure mutated filesystem: %#v / %v", entries, err)
	}
}

func reportWithoutArtifactFiles(accepted v1.AcceptedRequestRecord, attemptID string) v1.ExecutionReport {
	return v1.ExecutionReport{
		ProtocolVersion: v1.Version, RequestID: accepted.RequestID, RequestDigest: accepted.RequestDigest,
		AttemptID: attemptID, GatewaySourceSHA: strings.Repeat("c", 40), CommandStatus: v1.CommandStatusRuntimeFailed,
		ExitCode: nil, StartedAt: "2026-09-03T00:00:01Z", FinishedAt: "2026-09-03T00:00:02Z",
		DurationMilliseconds: 1000,
		Stdout:               v1.OutputMetadata{SHA256: strings.Repeat("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 1)},
		Stderr:               v1.OutputMetadata{SHA256: strings.Repeat("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 1)},
		Artifacts: v1.ArtifactManifest{
			Status: v1.ArtifactStatusFailed, Files: []v1.ArtifactFile{},
			Omissions: []v1.ArtifactOmission{{Group: "test-results", Pattern: "test-results/**/*.png", Reason: v1.ArtifactOmissionCollectionFailed}},
		},
	}
}
