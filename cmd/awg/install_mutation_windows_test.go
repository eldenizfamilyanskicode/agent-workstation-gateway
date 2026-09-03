//go:build windows

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/installer"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/runnerpackage"
	controltemplate "github.com/eldenizfamilyanskicode/agent-workstation-gateway/templates/control-repository"
)

const testInstallSourceSHA = "0123456789abcdef0123456789abcdef01234567"

type fakeInstallGitHub struct {
	operations   []string
	registration []byte
	removal      []byte
}

type fakeInstallLease struct {
	committed bool
	closed    bool
}

func (github *fakeInstallGitHub) CreatePersonalPrivate(context.Context) error {
	github.operations = append(github.operations, "create")
	return nil
}

func (github *fakeInstallGitHub) VerifyExclusivePrivate(context.Context) error {
	github.operations = append(github.operations, "verify-private-readers")
	return nil
}

func (github *fakeInstallGitHub) EnsureControlFile(_ context.Context, path string, content []byte) (bool, error) {
	if len(content) == 0 {
		return false, os.ErrInvalid
	}
	github.operations = append(github.operations, "file:"+path)
	return true, nil
}

func (github *fakeInstallGitHub) RegistrationToken(context.Context) ([]byte, error) {
	github.operations = append(github.operations, "registration-token")
	return github.registration, nil
}

func (github *fakeInstallGitHub) RemovalToken(context.Context) ([]byte, error) {
	github.operations = append(github.operations, "removal-token")
	return github.removal, nil
}

func (github *fakeInstallGitHub) Close() {
	github.operations = append(github.operations, "close")
}

func (lease *fakeInstallLease) Commit() error {
	lease.committed = true
	return nil
}

func (lease *fakeInstallLease) Close() error {
	lease.closed = true
	return nil
}

func TestMutatingInstallComposesPrivateBootstrapAndLocalTransaction(t *testing.T) {
	directory := t.TempDir()
	specPath := filepath.Join(directory, "install.json")
	specification, err := os.ReadFile(repositoryFile(t, "config", "examples", "v1", "windows-install.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(specPath, specification, 0o600); err != nil {
		t.Fatal(err)
	}
	brokerPath := writeInstallFixture(t, directory, "broker.exe", []byte("synthetic-broker"))
	controlPath := writeInstallFixture(t, directory, "control.exe", []byte("synthetic-control"))
	runnerArchive := syntheticRunnerArchive(t)
	runnerPath := writeInstallFixture(t, directory, "runner.zip", runnerArchive)
	digest := sha256.Sum256(runnerArchive)
	runnerImage, err := runnerpackage.Inspect("2.999.0", hex.EncodeToString(digest[:]), runnerArchive)
	if err != nil {
		t.Fatal(err)
	}
	humanToken := []byte("synthetic-human-token")
	registrationToken := []byte("synthetic-registration-token")
	removalToken := []byte("synthetic-removal-token")
	github := &fakeInstallGitHub{registration: registrationToken, removal: removalToken}
	lease := &fakeInstallLease{}
	deps := installDependencies{
		githubToken: func(context.Context) ([]byte, error) { return humanToken, nil },
		github: func(token []byte, repository string) (installGitHub, error) {
			if string(token) != "synthetic-human-token" || repository != "alice/example-control" {
				t.Fatal("GitHub client received unexpected authority")
			}
			return github, nil
		},
		render: controltemplate.Render,
		inspect: func(actual []byte) (*runnerpackage.Image, error) {
			if !bytes.Equal(actual, runnerArchive) {
				t.Fatal("runner archive changed")
			}
			return runnerImage, nil
		},
		validateImages: func(source string, broker []byte, control []byte) error {
			if source != testInstallSourceSHA || string(broker) != "synthetic-broker" || string(control) != "synthetic-control" {
				t.Fatal("release inputs changed")
			}
			return nil
		},
		provision: func(_ context.Context, input installer.Input) (installLease, error) {
			if input.GatewaySourceSHA != testInstallSourceSHA || input.RunnerImage != runnerImage ||
				input.RunnerRegistration.Repository.Name() != "alice/example-control" ||
				string(input.RunnerRegistration.RegistrationToken) != "synthetic-registration-token" ||
				string(input.RunnerRegistration.RemovalToken) != "synthetic-removal-token" {
				t.Fatal("installer received unbound input")
			}
			return lease, nil
		},
		start: func(context.Context) error {
			github.operations = append(github.operations, "start-services")
			return nil
		},
	}
	args := []string{
		"--spec", specPath, "--repository", "alice/example-control", "--create-repository",
		"--broker-image", brokerPath, "--control-image", controlPath, "--runner-archive", runnerPath,
		"--hosted-control-url", "https://github.com/eldenizfamilyanskicode/agent-workstation-gateway/releases/download/v0.1.0/awg-control-linux-amd64",
		"--hosted-control-sha256", "2222222222222222222222222222222222222222222222222222222222222222",
	}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	if exit := runInstallMutationWithDependencies(context.Background(), args, stdout, stderr, testInstallSourceSHA, deps); exit != 0 || stderr.Len() != 0 {
		t.Fatalf("install failed: exit=%d stderr=%q", exit, stderr.String())
	}
	expected := []string{
		"create", "verify-private-readers", "file:.github/workflows/execute-request.yml", "file:control-version.json",
		"registration-token", "removal-token", "start-services", "close",
	}
	if !reflect.DeepEqual(github.operations, expected) || !lease.committed || !lease.closed {
		t.Fatalf("unexpected lifecycle: operations=%#v lease=%#v", github.operations, lease)
	}
	for name, secret := range map[string][]byte{"human": humanToken, "registration": registrationToken, "removal": removalToken} {
		if !allZero(secret) {
			t.Fatalf("%s token was retained", name)
		}
	}
	if stdout.String() != "gateway installed\n" {
		t.Fatalf("unexpected output: %q", stdout.String())
	}
}

func writeInstallFixture(t *testing.T, directory string, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func syntheticRunnerArchive(t *testing.T) []byte {
	t.Helper()
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	for _, name := range []string{"bin/Runner.Listener.exe", "bin/RunnerService.exe"} {
		writer, err := archive.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte("synthetic runner file")); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func allZero(content []byte) bool {
	for _, value := range content {
		if value != 0 {
			return false
		}
	}
	return true
}
