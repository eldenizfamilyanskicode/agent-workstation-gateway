//go:build windows

package runnerstore

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/runnerpackage"
)

const syntheticExecutionSID = "S-1-5-21-3000-3000-3000-4300"

func TestProvisionExtractsProtectedRunnerAndRollbackOwnsExactTree(t *testing.T) {
	installationRoot := filepath.Join(t.TempDir(), "gateway")
	image := validImage(t)
	controlSID := currentAccountSID(t)
	lease, err := provisionFixture(context.Background(), installationRoot, controlSID, syntheticExecutionSID, image)
	if err != nil {
		t.Fatalf("%v: %v", err, errors.Unwrap(err))
	}
	layout, err := lease.Layout()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		layout.RunnerRoot,
		filepath.Join(layout.RunnerRoot, "bin"),
		layout.RunnerWorkDirectory,
		layout.RunnerResponseDirectory,
	} {
		if err := validateObject(path, true, lease.controlSID, lease.executionSID); err != nil {
			t.Fatalf("directory protection failed: %v", err)
		}
	}
	listener := filepath.Join(layout.RunnerRoot, "bin", "Runner.Listener.exe")
	if err := validateObject(listener, false, lease.controlSID, lease.executionSID); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(listener)
	if err != nil || string(content) != "listener" {
		t.Fatalf("runner content changed: %q / %v", content, err)
	}
	if err := lease.VerifyServiceExecutable(context.Background()); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(filepath.Dir(layout.RunnerRoot), "preserve.txt")
	if err := os.WriteFile(marker, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(layout.RunnerRoot); !os.IsNotExist(err) {
		t.Fatal("rollback left the create-owned runner root")
	}
	if content, err := os.ReadFile(marker); err != nil || string(content) != "preserve" {
		t.Fatal("rollback changed an unowned sibling")
	}
}

func TestProvisionCommitPreservesRunnerAndClosesLease(t *testing.T) {
	installationRoot := filepath.Join(t.TempDir(), "gateway")
	lease, err := provisionFixture(context.Background(), installationRoot, currentAccountSID(t), syntheticExecutionSID, validImage(t))
	if err != nil {
		t.Fatal(err)
	}
	layout, err := lease.Layout()
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(layout.RunnerRoot, "bin", "RunnerService.exe")); err != nil {
		t.Fatal("commit removed runner content")
	}
	if _, err := lease.Layout(); err == nil {
		t.Fatal("committed lease remained mutable")
	}
}

func TestProvisionRejectsExistingRunnerRootWithoutAdoption(t *testing.T) {
	parent := t.TempDir()
	installationRoot := filepath.Join(parent, "gateway")
	runnerRoot := installationRoot + "-runner"
	if err := os.Mkdir(runnerRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(runnerRoot, "preserve.txt")
	if err := os.WriteFile(marker, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := provisionFixture(context.Background(), installationRoot, currentAccountSID(t), syntheticExecutionSID, validImage(t)); err == nil {
		t.Fatal("pre-existing runner root was adopted")
	}
	content, err := os.ReadFile(marker)
	if err != nil || string(content) != "preserve" {
		t.Fatal("failed provision changed pre-existing runner content")
	}
}

func TestProvisionRejectsInvalidOrEqualIdentitiesBeforeMutation(t *testing.T) {
	parent := t.TempDir()
	installationRoot := filepath.Join(parent, "gateway")
	control := currentAccountSID(t)
	for _, identifiers := range [][2]string{{"S-1-5-18", syntheticExecutionSID}, {control, control}} {
		if _, err := provisionFixture(context.Background(), installationRoot, identifiers[0], identifiers[1], validImage(t)); err == nil {
			t.Fatal("invalid identity policy was accepted")
		}
		if _, err := os.Stat(installationRoot + "-runner"); !os.IsNotExist(err) {
			t.Fatal("invalid identity policy mutated runner storage")
		}
	}
}

func TestExportedProvisionRejectsUnpinnedPackageBeforeMutation(t *testing.T) {
	installationRoot := filepath.Join(t.TempDir(), "gateway")
	if _, err := Provision(context.Background(), installationRoot, currentAccountSID(t), syntheticExecutionSID, validImage(t)); err == nil {
		t.Fatal("caller-paired archive and digest reached runner storage mutation")
	}
	if _, err := os.Stat(installationRoot + "-runner"); !os.IsNotExist(err) {
		t.Fatal("unpinned package mutated runner storage")
	}
}

func TestSealGeneratedStateProtectsVerifiesAndRollsBackConfiguration(t *testing.T) {
	installationRoot := filepath.Join(t.TempDir(), "gateway")
	lease, err := provisionFixture(context.Background(), installationRoot, currentAccountSID(t), syntheticExecutionSID, validImage(t))
	if err != nil {
		t.Fatal(err)
	}
	layout, err := lease.Layout()
	if err != nil {
		t.Fatal(err)
	}
	diagnosticDirectory := filepath.Join(layout.RunnerRoot, "_diag")
	if err := os.Mkdir(diagnosticDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(layout.RunnerRoot, ".runner"),
		filepath.Join(layout.RunnerRoot, ".credentials"),
		filepath.Join(layout.RunnerRoot, ".credentials_rsaparams"),
		filepath.Join(diagnosticDirectory, "Runner_1.log"),
	} {
		if err := os.WriteFile(path, []byte("synthetic generated state"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := lease.SealGeneratedState(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lease.VerifyRegistrationState(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		diagnosticDirectory,
		filepath.Join(layout.RunnerRoot, ".runner"),
		filepath.Join(layout.RunnerRoot, ".credentials"),
		filepath.Join(layout.RunnerRoot, ".credentials_rsaparams"),
		filepath.Join(diagnosticDirectory, "Runner_1.log"),
	} {
		information, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateObject(path, information.IsDir(), lease.controlSID, lease.executionSID); err != nil {
			t.Fatalf("generated object was not protected: %v", err)
		}
	}
	// Runner.Listener remove deletes its own registration files before the
	// outer storage lease rolls back the remaining create-owned tree.
	for _, name := range []string{".runner", ".credentials", ".credentials_rsaparams"} {
		if err := os.Remove(filepath.Join(layout.RunnerRoot, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(layout.RunnerRoot); !os.IsNotExist(err) {
		t.Fatal("rollback left generated registration state")
	}
}

func TestVerifyRegistrationStateRejectsIncompleteGeneratedState(t *testing.T) {
	installationRoot := filepath.Join(t.TempDir(), "gateway")
	lease, err := provisionFixture(context.Background(), installationRoot, currentAccountSID(t), syntheticExecutionSID, validImage(t))
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	layout, err := lease.Layout()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layout.RunnerRoot, ".runner"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := lease.SealGeneratedState(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lease.VerifyRegistrationState(context.Background()); err == nil {
		t.Fatal("partial runner registration state was accepted")
	}
}

func validImage(t *testing.T) *runnerpackage.Image {
	t.Helper()
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for path, content := range map[string]string{
		"bin/Runner.Listener.exe": "listener",
		"bin/RunnerService.exe":   "service",
		"externals/tool.dll":      "tool",
	} {
		destination, err := writer.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := destination.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	encoded := archive.Bytes()
	sum := sha256.Sum256(encoded)
	image, err := runnerpackage.Inspect("2.337.0", hex.EncodeToString(sum[:]), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return image
}

func provisionFixture(
	ctx context.Context,
	installationRoot, controlIdentifier, executionIdentifier string,
	image *runnerpackage.Image,
) (*Lease, error) {
	return provision(ctx, installationRoot, controlIdentifier, executionIdentifier, image, false)
}

func currentAccountSID(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("current user SID: %v", err)
	}
	identifier := user.User.Sid.String()
	if !strings.HasPrefix(identifier, "S-1-5-21-") {
		t.Skipf("current test identity is not a local/domain account: %s", identifier)
	}
	return identifier
}
