//go:build windows

package controlresponse

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/brokerwire"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

func TestDestinationPublishesCompleteResponseAtomically(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "responses")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	finalPath := filepath.Join(parent, "attempt-000001")
	destination, err := New(finalPath)
	if err != nil {
		t.Fatal(err)
	}
	artifactContent := []byte("synthetic artifact")
	artifact := v1.ArtifactFile{
		Group: "results", Path: "nested/result.txt", SHA256: digest(artifactContent), SizeBytes: int64(len(artifactContent)),
	}
	transaction, err := destination.Begin([]v1.ArtifactFile{artifact})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := transaction.Open(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(artifactContent); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
	if exists(finalPath) {
		t.Fatal("artifact transaction exposed the final destination before response publication")
	}
	report := validReport([]byte("stdout"), []byte("stderr"), v1.ArtifactManifest{
		Status: v1.ArtifactStatusComplete, Files: []v1.ArtifactFile{artifact}, Omissions: []v1.ArtifactOmission{},
	})
	if err := destination.Publish(brokerwire.Response{Report: report, Stdout: []byte("stdout"), Stderr: []byte("stderr")}); err != nil {
		t.Fatal(err)
	}
	assertFileContent(t, filepath.Join(finalPath, stdoutName), []byte("stdout"))
	assertFileContent(t, filepath.Join(finalPath, stderrName), []byte("stderr"))
	assertFileContent(t, filepath.Join(finalPath, artifactsName, "results", "nested", "result.txt"), artifactContent)
	encodedReport, err := v1.MarshalCanonicalExecutionReport(report)
	if err != nil {
		t.Fatal(err)
	}
	assertFileContent(t, filepath.Join(finalPath, reportName), encodedReport)
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(finalPath) {
		t.Fatalf("staging entries remained after publication: %#v / %v", entries, err)
	}
	if err := destination.Abort(); err != nil || !exists(finalPath) {
		t.Fatal("abort removed an already published destination")
	}
}

func TestDestinationPublishesEmptyOutputWithoutArtifactTransaction(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "responses")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	finalPath := filepath.Join(parent, "attempt-empty")
	destination, err := New(finalPath)
	if err != nil {
		t.Fatal(err)
	}
	report := validReport(nil, nil, v1.ArtifactManifest{
		Status: v1.ArtifactStatusNotRequested, Files: []v1.ArtifactFile{}, Omissions: []v1.ArtifactOmission{},
	})
	if err := destination.Publish(brokerwire.Response{Report: report, Stdout: []byte{}, Stderr: []byte{}}); err != nil {
		t.Fatal(err)
	}
	assertFileContent(t, filepath.Join(finalPath, stdoutName), nil)
	assertFileContent(t, filepath.Join(finalPath, stderrName), nil)
}

func TestDestinationAbortRemovesOnlyOwnedStagingObjects(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "responses")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(parent, "preserve.txt")
	if err := os.WriteFile(marker, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	destination, err := New(filepath.Join(parent, "attempt-abort"))
	if err != nil {
		t.Fatal(err)
	}
	staging := destination.stagingPath
	artifact := v1.ArtifactFile{Group: "logs", Path: "deep/output.log", SHA256: digest(nil), SizeBytes: 0}
	transaction, err := destination.Begin([]v1.ArtifactFile{artifact})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := transaction.Open(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Abort(); err != nil {
		t.Fatal(err)
	}
	if exists(staging) {
		t.Fatal("abort left staging content")
	}
	assertFileContent(t, marker, []byte("preserve"))
	if err := destination.Abort(); err != nil {
		t.Fatal("abort was not idempotent")
	}
}

func TestDestinationRejectsExistingAndRootLevelFinalPaths(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "responses")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(parent, "existing")
	if err := os.Mkdir(existing, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := New(existing)
	assertDestinationError(t, err, "final-path-exists")
	volumeRoot := filepath.VolumeName(parent) + `\`
	_, err = New(filepath.Join(volumeRoot, "root-level-denied"))
	assertDestinationError(t, err, "parent-root-denied")
}

func TestDestinationRejectsReparseParent(t *testing.T) {
	root := t.TempDir()
	realParent := filepath.Join(root, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	linkParent := filepath.Join(root, "link")
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Skipf("host cannot create a directory symlink: %v", err)
	}
	_, err := New(filepath.Join(linkParent, "attempt"))
	assertDestinationError(t, err, "parent-directory-denied")
}

func TestDestinationRefusesCollisionCreatedBeforePublish(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "responses")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	finalPath := filepath.Join(parent, "attempt-race")
	destination, err := New(finalPath)
	if err != nil {
		t.Fatal(err)
	}
	staging := destination.stagingPath
	if err := os.Mkdir(finalPath, 0o700); err != nil {
		t.Fatal(err)
	}
	report := validReport(nil, nil, v1.ArtifactManifest{
		Status: v1.ArtifactStatusNotRequested, Files: []v1.ArtifactFile{}, Omissions: []v1.ArtifactOmission{},
	})
	err = destination.Publish(brokerwire.Response{Report: report, Stdout: []byte{}, Stderr: []byte{}})
	assertDestinationError(t, err, "final-path-unavailable")
	if err := destination.Abort(); err != nil || exists(staging) == true || !exists(finalPath) {
		t.Fatal("failed publication did not preserve collision and remove staging")
	}
}

func TestArtifactTransactionEnforcesExactOrderAndCompletion(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "responses")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	destination, err := New(filepath.Join(parent, "attempt-order"))
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Abort()
	first := v1.ArtifactFile{Group: "logs", Path: "first.txt", SHA256: digest(nil), SizeBytes: 0}
	second := v1.ArtifactFile{Group: "logs", Path: "second.txt", SHA256: digest(nil), SizeBytes: 0}
	transaction, err := destination.Begin([]v1.ArtifactFile{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Open(second); err == nil {
		t.Fatal("artifact transaction accepted an out-of-order destination")
	}
	writer, err := transaction.Open(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(); err == nil {
		t.Fatal("artifact transaction committed with an open destination")
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(); err == nil {
		t.Fatal("artifact transaction committed before every expected file")
	}
}

func TestDestinationRejectsCaseAliasedArtifactCollision(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "responses")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	destination, err := New(filepath.Join(parent, "attempt-alias"))
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Abort()
	first := v1.ArtifactFile{Group: "logs", Path: "Result.txt", SHA256: digest(nil), SizeBytes: 0}
	second := v1.ArtifactFile{Group: "logs", Path: "result.txt", SHA256: digest(nil), SizeBytes: 0}
	_, err = destination.Begin([]v1.ArtifactFile{first, second})
	assertDestinationError(t, err, "artifact-list-invalid")

	otherGroup := second
	otherGroup.Group = "Logs"
	otherGroup.Path = "other.txt"
	_, err = destination.Begin([]v1.ArtifactFile{first, otherGroup})
	assertDestinationError(t, err, "artifact-list-invalid")
}

func TestDestinationRejectsWindowsReservedArtifactName(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "responses")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	destination, err := New(filepath.Join(parent, "attempt-reserved"))
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Abort()
	reserved := v1.ArtifactFile{Group: "logs", Path: "CON.txt", SHA256: digest(nil), SizeBytes: 0}
	_, err = destination.Begin([]v1.ArtifactFile{reserved})
	assertDestinationError(t, err, "artifact-list-invalid")
}

func validReport(stdout []byte, stderr []byte, artifacts v1.ArtifactManifest) v1.ExecutionReport {
	exitCode := int64(0)
	return v1.ExecutionReport{
		ProtocolVersion: v1.Version, RequestID: "request-1", RequestDigest: strings.Repeat("a", 64),
		AttemptID: "attempt-1", GatewaySourceSHA: strings.Repeat("b", 40), CommandStatus: v1.CommandStatusCompleted,
		ExitCode: &exitCode, StartedAt: "2026-09-03T00:00:01Z", FinishedAt: "2026-09-03T00:00:02Z",
		DurationMilliseconds: 1000,
		Stdout:               v1.OutputMetadata{SHA256: digest(stdout), TotalBytes: int64(len(stdout)), RetainedBytes: int64(len(stdout))},
		Stderr:               v1.OutputMetadata{SHA256: digest(stderr), TotalBytes: int64(len(stderr)), RetainedBytes: int64(len(stderr))},
		Artifacts:            artifacts,
	}
}

func assertFileContent(t *testing.T, path string, expected []byte) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(content, expected) {
		t.Fatalf("file content changed: %q / %v", content, err)
	}
}

func assertDestinationError(t *testing.T, err error, rule string) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Rule != rule {
		t.Fatalf("expected destination error %q, got %T / %v", rule, err, err)
	}
}

func digest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}
