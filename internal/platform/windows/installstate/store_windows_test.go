//go:build windows

package installstate

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

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
