//go:build windows

package installstate

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateNewProtectedDirectoryDoesNotAdoptExistingDirectory(t *testing.T) {
	directory := t.TempDir()
	created, err := (NativeStore{}).CreateNewProtectedDirectory(directory)
	if created {
		t.Fatal("pre-existing directory was reported as transaction-owned")
	}
	assertStoreRule(t, err, "directory-already-exists")
	if information, statErr := os.Stat(directory); statErr != nil || !information.IsDir() {
		t.Fatal("pre-existing directory was removed or replaced")
	}
}

func TestNativeStoreRejectsOrdinaryParentWithoutCreatingArtifact(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "installation.json")
	err := (NativeStore{}).WriteProtectedFile(target, []byte("synthetic-state"))
	if err == nil {
		t.Fatal("ordinary user-owned parent directory was accepted as protected state")
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatal("rejected protected-state write created its target")
	}
	entries, readErr := os.ReadDir(directory)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatal("rejected protected-state write left a temporary artifact")
	}
}

func TestNativeStoreRejectsNewExecutableUnderOrdinaryParent(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "awg-broker.exe")
	created, err := (NativeStore{}).WriteNewProtectedExecutable(target, []byte("synthetic-image"))
	if err == nil || created {
		t.Fatal("ordinary user-owned parent accepted a protected executable")
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatal("rejected protected executable write created its target")
	}
}

func TestNativeStoreRejectsEmptyExecutableBeforeFilesystemAccess(t *testing.T) {
	created, err := (NativeStore{}).WriteNewProtectedExecutable(
		`C:\ProgramData\AgentWorkstationGateway\bin\awg-broker.exe`, nil,
	)
	if created {
		t.Fatal("empty executable was reported as created")
	}
	assertStoreRule(t, err, "file-content-invalid")
}

func TestDPAPISealerDoesNotReturnPlaintext(t *testing.T) {
	password := []byte("Synthetic-only-password-764b!")
	protected, err := (DPAPISealer{}).Seal(password)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(protected, password) {
		t.Fatal("DPAPI sealer output contains plaintext")
	}
	for index := range password {
		password[index] = 0
	}
}

func assertStoreRule(t *testing.T, err error, rule string) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Rule != rule {
		t.Fatalf("expected %s, got %T / %v", rule, err, err)
	}
}
