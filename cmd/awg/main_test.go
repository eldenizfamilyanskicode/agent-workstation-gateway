package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
)

func TestInstallDryRunPrintsPlanWithoutMutation(t *testing.T) {
	directory := t.TempDir()
	specificationPath := filepath.Join(directory, "install.json")
	example, err := os.ReadFile(repositoryFile(t, "config", "examples", "v1", "windows-install.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(specificationPath, example, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run(context.Background(), []string{"install", "--dry-run", "--spec", specificationPath}, &stdout, &stderr)
	if exitCode != 0 || stderr.Len() != 0 {
		t.Fatalf("dry-run failed: exit=%d stderr=%q", exitCode, stderr.String())
	}
	var plan installplan.Plan
	if err := json.Unmarshal(stdout.Bytes(), &plan); err != nil || len(plan.Operations) == 0 {
		t.Fatal("dry-run did not emit a valid nonempty plan")
	}
	after, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) {
		t.Fatal("dry-run changed the specification directory")
	}
	current, err := os.ReadFile(specificationPath)
	if err != nil || !bytes.Equal(current, example) {
		t.Fatal("dry-run changed its input specification")
	}
}

func TestInstallMutationRequiresCompletePlatformInputs(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run(context.Background(), []string{"install", "--spec", "synthetic.json"}, &stdout, &stderr)
	expected := 2
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		expected = 1
	}
	if exitCode != expected || stdout.Len() != 0 || stderr.Len() == 0 {
		t.Fatal("install accepted incomplete mutation inputs")
	}
}

func TestInstallRejectsOversizedSpecWithoutEchoingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "synthetic-private-marker.json")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, installplan.MaxSpecBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run(context.Background(), []string{"install", "--dry-run", "--spec", path}, &stdout, &stderr)
	if exitCode != 1 || stdout.Len() != 0 || bytes.Contains(stderr.Bytes(), []byte(path)) {
		t.Fatal("oversized input handling was not closed and non-echoing")
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
