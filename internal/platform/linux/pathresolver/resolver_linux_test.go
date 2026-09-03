//go:build linux

package pathresolver

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

func TestResolveWithinRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := (Resolver{}).ResolveWithin(context.Background(), platformpath.Linux, link, []string{root}); err == nil {
		t.Fatal("symlink escape was accepted")
	}
}

func TestResolveWithinReturnsStableDirectory(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "project")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	resolution, err := (Resolver{}).ResolveWithin(context.Background(), platformpath.Linux, child, []string{root})
	if err != nil || resolution.WorkingDirectory != child || resolution.ApprovedRoot != root {
		t.Fatalf("unexpected resolution: %#v, %v", resolution, err)
	}
}
