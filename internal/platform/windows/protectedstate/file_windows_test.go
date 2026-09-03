//go:build windows

package protectedstate

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestExactFileRejectsInvalidPolicyBeforeOpening(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		maximum int
	}{
		{name: "relative path", path: `relative\state.json`, maximum: 64},
		{name: "zero maximum", path: `C:\ProgramData\AWG\state.json`, maximum: 0},
		{name: "excessive maximum", path: `C:\ProgramData\AWG\state.json`, maximum: MaxProtectedFileBytes + 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertFileRule(t, ValidateExactFile(test.path, test.maximum), "file-policy-invalid")
		})
	}
}

func TestExactExecutableHasAnIndependentBoundedPolicy(t *testing.T) {
	path := `C:\ProgramData\AWG\bin\awg-broker.exe`
	assertFileRule(t, ValidateExactExecutable(path, 0), "file-policy-invalid")
	assertFileRule(t, ValidateExactExecutable(path, MaxProtectedExecutableBytes+1), "file-policy-invalid")
	assertFileRule(t, ValidateExactFile(path, MaxProtectedFileBytes+1), "file-policy-invalid")

	// A maximum valid only for executables reaches the native open boundary;
	// it is not rejected as a state-file policy and no fixture is created.
	assertFileRule(t, ValidateExactExecutable(path, MaxProtectedFileBytes+1), "file-open-failed")
}

func TestExactFileRejectsEmptyAndOversizedFilesBeforeACLValidation(t *testing.T) {
	directory := t.TempDir()
	empty := filepath.Join(directory, "empty.json")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal("could not create empty fixture")
	}
	assertFileRule(t, ValidateExactFile(empty, 64), "file-shape-denied")

	oversized := filepath.Join(directory, "oversized.json")
	if err := os.WriteFile(oversized, bytes.Repeat([]byte{'x'}, 65), 0o600); err != nil {
		t.Fatal("could not create oversized fixture")
	}
	assertFileRule(t, ValidateExactFile(oversized, 64), "file-shape-denied")
}

func TestExactFileRejectsHardLinksBeforeACLValidation(t *testing.T) {
	directory := t.TempDir()
	original := filepath.Join(directory, "state.json")
	alias := filepath.Join(directory, "state-link.json")
	if err := os.WriteFile(original, []byte("synthetic-state"), 0o600); err != nil {
		t.Fatal("could not create state fixture")
	}
	if err := os.Link(original, alias); err != nil {
		t.Fatal("could not create hard-link fixture")
	}
	assertFileRule(t, ValidateExactFile(original, 64), "file-link-denied")
}

func TestExactFileDoesNotEchoRejectedPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ordinary-state.json")
	if err := os.WriteFile(path, []byte("synthetic-state"), 0o600); err != nil {
		t.Fatal("could not create state fixture")
	}
	content, err := ReadExactFile(path, 64)
	if content != nil {
		zero(content)
		t.Fatal("ordinary user-owned state file was accepted")
	}
	if err == nil {
		t.Fatal("ordinary user-owned state file was not denied")
	}
	if bytes.Contains([]byte(err.Error()), []byte(path)) {
		t.Fatal("protected-state denial echoed the configured path")
	}
}

func assertFileRule(t *testing.T, err error, rule string) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Rule != rule {
		t.Fatalf("expected %s, got %T / %v", rule, err, err)
	}
}
