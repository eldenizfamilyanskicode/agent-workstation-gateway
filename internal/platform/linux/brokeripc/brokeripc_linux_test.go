//go:build linux

package brokeripc

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

func TestServerRejectsWrongPeerUID(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to set the socket policy")
	}
	_ = os.Remove(SocketPath)
	_ = os.Remove(SocketDirectory)
	server, err := NewServer(testConfiguration())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = server.Close()
		_ = os.Remove(SocketDirectory)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	accepted := make(chan error, 1)
	go func() {
		connection, acceptErr := server.Accept(ctx)
		if connection != nil {
			_ = connection.Close()
		}
		accepted <- acceptErr
	}()
	connection, err := Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if err := <-accepted; err == nil {
		t.Fatal("root peer was accepted for the execution-control UID")
	}
}

func testConfiguration() installconfig.Config {
	return installconfig.Config{ConfigVersion: 1, Platform: platformpath.Linux,
		ControlIdentity:   installconfig.Principal{Name: "awg-control", Identifier: "uid:65534", PrimaryGroupIdentifier: "gid:65534"},
		ExecutionIdentity: installconfig.Principal{Name: "awg-exec", Identifier: "uid:65533", PrimaryGroupIdentifier: "gid:65533"},
		ApprovedRoots:     []string{"/srv/awg/projects"}, Shells: []installconfig.ShellBinding{{Shell: v1.ShellBash, Executable: "/bin/bash"}},
		ProfileRoot: "/var/lib/awg-exec", TempRoot: "/var/tmp/awg-exec", PathEntries: []string{"/usr/bin", "/bin"}, Capabilities: []installconfig.Capability{}}
}
