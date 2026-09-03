//go:build linux

package artifact

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionrun"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == HelperOperation {
		os.Exit(RunHelper(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func TestCollectorReadsAsExecutionIdentityAndRejectsLink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to verify the artifact identity boundary")
	}
	working, err := os.MkdirTemp("", "awg-artifact-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(working) })
	if err := os.Chmod(working, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(working, "result.txt"), []byte("expected"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(working, "leak.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("/run/agent-workstation-gateway", 0o750); err != nil {
		t.Fatal(err)
	}
	collector, err := New(artifactConfiguration(working))
	if err != nil {
		t.Fatal(err)
	}
	identity := installconfig.Principal{Name: "awg-exec", Identifier: "uid:65534", PrimaryGroupIdentifier: "gid:65534"}
	collection, err := collector.Collect(context.Background(), executionrun.ArtifactPlan{ExecutionIdentity: identity, WorkingDirectory: working,
		ApprovedRoot: working, Selections: []v1.ArtifactSelection{{Name: "results", Paths: []string{"*.txt"}}}})
	if err != nil {
		t.Fatal(err)
	}
	defer collection.Bundle.Close()
	if len(collection.Manifest.Files) != 1 || collection.Manifest.Files[0].Path != "result.txt" || len(collection.Manifest.Omissions) != 1 ||
		collection.Manifest.Omissions[0].Reason != v1.ArtifactOmissionLinkRejected {
		t.Fatalf("unexpected manifest: %#v", collection.Manifest)
	}
	file, err := collection.Bundle.Open("results", "result.txt")
	if err != nil {
		t.Fatal(err)
	}
	content, readErr := io.ReadAll(file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || string(content) != "expected" {
		t.Fatalf("unexpected artifact: %q, %v, %v", content, readErr, closeErr)
	}
}

func artifactConfiguration(root string) installconfig.Config {
	return installconfig.Config{ConfigVersion: 1, Platform: platformpath.Linux,
		ControlIdentity:   installconfig.Principal{Name: "awg-control", Identifier: "uid:65533", PrimaryGroupIdentifier: "gid:65533"},
		ExecutionIdentity: installconfig.Principal{Name: "awg-exec", Identifier: "uid:65534", PrimaryGroupIdentifier: "gid:65534"},
		ApprovedRoots:     []string{root}, Shells: []installconfig.ShellBinding{{Shell: v1.ShellBash, Executable: "/bin/bash"}},
		ProfileRoot: "/var/lib/awg-exec", TempRoot: "/var/tmp/awg-exec", PathEntries: []string{"/usr/bin", "/bin"}, Capabilities: []installconfig.Capability{}}
}
