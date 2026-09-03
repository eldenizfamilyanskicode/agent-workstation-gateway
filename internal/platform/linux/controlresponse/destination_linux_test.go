//go:build linux

package controlresponse

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewRejectsSymlinkInDestinationChain(t *testing.T) {
	realParent := filepath.Join(t.TempDir(), "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(realParent, link); err != nil {
		t.Fatal(err)
	}
	if _, err := New(filepath.Join(link, "response")); err == nil {
		t.Fatal("symlinked destination chain was accepted")
	}
}

func TestAbortRemovesOwnedStagingDirectory(t *testing.T) {
	parent := t.TempDir()
	destination, err := New(filepath.Join(parent, "response"))
	if err != nil {
		t.Fatal(err)
	}
	staging := destination.stagingPath
	if err := destination.Abort(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(staging); !os.IsNotExist(err) {
		t.Fatal("staging directory remained after abort")
	}
}
