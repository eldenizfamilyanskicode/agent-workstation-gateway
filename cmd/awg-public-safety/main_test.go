package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunCleanRepository(t *testing.T) {
	repo := newCLIRepo(t)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(context.Background(), []string{"-repo", repo, "-scope", "all"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d, stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "public safety scan passed") {
		t.Fatalf("missing pass output: %q", stdout.String())
	}
}

func TestRunFindingRedactsOperatorValueAndClearsEnvironment(t *testing.T) {
	repo := newCLIRepo(t)
	privateMarker := strings.Join([]string{"SYNTHETIC-PRIVATE-", "4242"}, "")
	path := filepath.ToSlash(filepath.Join("notes", privateMarker+".txt"))
	writeCLIFile(t, repo, path, "synthetic content")
	gitCLI(t, repo, "add", path)
	t.Setenv(forbiddenLiteralEnv, privateMarker)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(context.Background(), []string{"-repo", repo, "-scope", "staged"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d, stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), privateMarker) || strings.Contains(stderr.String(), privateMarker) {
		t.Fatalf("operator value leaked: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "<redacted>") {
		t.Fatalf("expected redacted path, got %q", stdout.String())
	}
	if os.Getenv(forbiddenLiteralEnv) != "" {
		t.Fatal("forbidden literal environment was not cleared")
	}
}

func TestRunInvalidOperatorRegexDoesNotLeak(t *testing.T) {
	repo := newCLIRepo(t)
	privatePattern := strings.Join([]string{"SYNTHETIC-PRIVATE-", "["}, "")
	t.Setenv(forbiddenRegexEnv, privatePattern)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(context.Background(), []string{"-repo", repo, "-scope", "current"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if strings.Contains(stdout.String(), privatePattern) || strings.Contains(stderr.String(), privatePattern) {
		t.Fatalf("operator regex leaked: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if os.Getenv(forbiddenRegexEnv) != "" {
		t.Fatal("forbidden regex environment was not cleared")
	}
}

func newCLIRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	gitCLI(t, repo, "init")
	gitCLI(t, repo, "config", "user.name", "Alice Example")
	gitCLI(t, repo, "config", "user.email", "alice@example.invalid")
	writeCLIFile(t, repo, "README.md", "# Synthetic repository\n")
	gitCLI(t, repo, "add", "README.md")
	gitCLI(t, repo, "commit", "-m", "Initial synthetic commit")
	return repo
}

func writeCLIFile(t *testing.T, repo, path, content string) {
	t.Helper()
	fullPath := filepath.Join(repo, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func gitCLI(t *testing.T, repo string, args ...string) {
	t.Helper()
	commandArgs := append([]string{"-C", repo}, args...)
	cmd := exec.Command("git", commandArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, output)
	}
}
