package publicsafety

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanCleanRepository(t *testing.T) {
	repo := newSyntheticRepo(t)
	findings, err := Scan(context.Background(), Options{Repo: repo, Scope: ScopeAll})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected clean repository, got %#v", findings)
	}
}

func TestScanForbiddenRuntimePath(t *testing.T) {
	repo := newSyntheticRepo(t)
	writeSyntheticFile(t, repo, ".runtime/results/000001/result.json", "{}")
	gitSynthetic(t, repo, "add", ".runtime/results/000001/result.json")

	findings := mustScan(t, Options{Repo: repo, Scope: ScopeStaged})
	assertRule(t, findings, "forbidden-runtime-state")
}

func TestScanGenericSecretForms(t *testing.T) {
	repo := newSyntheticRepo(t)
	privateKey := strings.Join([]string{"-----BEGIN ", "PRIVATE KEY-----"}, "")
	pgpPrivateKey := strings.Join([]string{"-----BEGIN PGP PRIVATE ", "KEY BLOCK-----"}, "")
	fakeToken := "gh" + "p_" + strings.Repeat("A", 40)
	writeSyntheticFile(t, repo, "synthetic.txt", privateKey+"\n"+pgpPrivateKey+"\n"+fakeToken+"\n")
	gitSynthetic(t, repo, "add", "synthetic.txt")

	findings := mustScan(t, Options{Repo: repo, Scope: ScopeStaged})
	assertRule(t, findings, "secret-private-key")
	assertRule(t, findings, "secret-pgp-private-key")
	assertRule(t, findings, "secret-github-token")
}

func TestScanStagedEnvironmentFile(t *testing.T) {
	repo := newSyntheticRepo(t)
	writeSyntheticFile(t, repo, ".env", "EXAMPLE_ONLY=synthetic")
	gitSynthetic(t, repo, "add", ".env")

	findings := mustScan(t, Options{Repo: repo, Scope: ScopeStaged})
	assertRule(t, findings, "environment-secret-file")
}

func TestScanHistoryFindsDeletedResidue(t *testing.T) {
	repo := newSyntheticRepo(t)
	fakeToken := "gh" + "s_" + strings.Repeat("B", 40)
	writeSyntheticFile(t, repo, "historical.txt", fakeToken)
	gitSynthetic(t, repo, "add", "historical.txt")
	gitSynthetic(t, repo, "commit", "-m", "Add synthetic historical fixture")
	if err := os.Remove(filepath.Join(repo, "historical.txt")); err != nil {
		t.Fatal(err)
	}
	gitSynthetic(t, repo, "add", "-u")
	gitSynthetic(t, repo, "commit", "-m", "Remove synthetic historical fixture")

	findings := mustScan(t, Options{Repo: repo, Scope: ScopeHistory})
	assertRule(t, findings, "secret-github-token")
}

func TestScanOperatorSuppliedPrivateValues(t *testing.T) {
	repo := newSyntheticRepo(t)
	writeSyntheticFile(t, repo, "note.txt", "synthetic marker ALICE-INTERNAL-4242")
	gitSynthetic(t, repo, "add", "note.txt")

	findings := mustScan(t, Options{
		Repo:              repo,
		Scope:             ScopeStaged,
		ForbiddenLiterals: []string{"ALICE-INTERNAL"},
		ForbiddenRegexes:  []string{`INTERNAL-[0-9]{4}`},
	})
	assertRule(t, findings, "operator-literal-01")
	assertRule(t, findings, "operator-regex-01")
}

func TestScanWorkflowSafety(t *testing.T) {
	tests := []struct {
		name string
		body string
		rule string
	}{
		{name: "self hosted", body: "jobs:\n  test:\n    runs-on: self-hosted\n", rule: "workflow-self-hosted"},
		{name: "pull request target", body: "on:\n  pull_request_target:\n", rule: "workflow-pull-request-target"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repo := newSyntheticRepo(t)
			writeSyntheticFile(t, repo, ".github/workflows/test.yml", test.body)
			gitSynthetic(t, repo, "add", ".github/workflows/test.yml")
			findings := mustScan(t, Options{Repo: repo, Scope: ScopeStaged})
			assertRule(t, findings, test.rule)
		})
	}
}

func TestInvalidOperatorRegexDoesNotEchoPattern(t *testing.T) {
	repo := newSyntheticRepo(t)
	privatePattern := strings.Join([]string{"ALICE-PRIVATE", "-["}, "")
	_, err := Scan(context.Background(), Options{Repo: repo, Scope: ScopeCurrent, ForbiddenRegexes: []string{privatePattern}})
	if err == nil {
		t.Fatal("expected invalid regex error")
	}
	if strings.Contains(err.Error(), privatePattern) {
		t.Fatalf("error leaked operator pattern: %q", err)
	}
}

func mustScan(t *testing.T, options Options) []Finding {
	t.Helper()
	findings, err := Scan(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func assertRule(t *testing.T, findings []Finding, rule string) {
	t.Helper()
	for _, finding := range findings {
		if finding.Rule == rule {
			return
		}
	}
	t.Fatalf("expected rule %q in %#v", rule, findings)
}

func newSyntheticRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	gitSynthetic(t, repo, "init")
	gitSynthetic(t, repo, "config", "user.name", "Alice Example")
	gitSynthetic(t, repo, "config", "user.email", "alice@example.invalid")
	writeSyntheticFile(t, repo, "README.md", "# Synthetic repository\n")
	gitSynthetic(t, repo, "add", "README.md")
	gitSynthetic(t, repo, "commit", "-m", "Initial synthetic commit")
	return repo
}

func writeSyntheticFile(t *testing.T, repo, path, content string) {
	t.Helper()
	fullPath := filepath.Join(repo, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func gitSynthetic(t *testing.T, repo string, args ...string) {
	t.Helper()
	commandArgs := append([]string{"-C", repo}, args...)
	cmd := exec.Command("git", commandArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, output)
	}
}
