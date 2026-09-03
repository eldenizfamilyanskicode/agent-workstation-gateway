//go:build linux

package uninstaller

import "testing"

func TestRemoveExactTreeRejectsFilesystemRoot(t *testing.T) {
	if err := removeExactTree("/"); err == nil {
		t.Fatal("filesystem root removal was accepted")
	}
}
