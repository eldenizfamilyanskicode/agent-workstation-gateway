//go:build windows

package installer

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installmetadata"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	sharedstate "github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installstate"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/runnerpackage"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/runnerregistration"
)

type transactionHarness struct {
	operations        []string
	failures          map[string]error
	account           *fakeAccountTransaction
	filesystem        *fakeLifecycleTransaction
	root              *fakeRootTransaction
	service           *fakeLifecycleTransaction
	runnerStorage     *fakeRunnerStorageTransaction
	registration      *fakeLifecycleTransaction
	runnerService     *fakeLifecycleTransaction
	executionOriginal []byte
	controlOriginal   []byte
	badReceipt        bool
	onService         func()
}

type fakeAccountTransaction struct {
	harness   *transactionHarness
	binding   installplan.IdentityBinding
	control   []byte
	execution []byte
}

type fakeLifecycleTransaction struct {
	harness *transactionHarness
	name    string
}

type fakeRootTransaction struct {
	harness *transactionHarness
	layout  installplan.Layout
}

type fakeRunnerStorageTransaction struct {
	harness *transactionHarness
}

type fakeSealer struct {
	harness *transactionHarness
}

func newTransactionHarness(t *testing.T) *transactionHarness {
	t.Helper()
	layout, err := installplan.WindowsLayout(installerSpec().InstallationRoot)
	if err != nil {
		t.Fatal(err)
	}
	harness := &transactionHarness{failures: make(map[string]error)}
	harness.controlOriginal = []byte("Synthetic-control-password-transaction-1!")
	harness.executionOriginal = []byte("Synthetic-execution-password-transaction-2!")
	harness.account = &fakeAccountTransaction{
		harness: harness,
		binding: installplan.IdentityBinding{
			ControlIdentifier: "S-1-5-21-2000-2000-2000-1001", ControlPrimaryGroupIdentifier: "S-1-5-32-545",
			ExecutionIdentifier: "S-1-5-21-2000-2000-2000-1002", ExecutionPrimaryGroupIdentifier: "S-1-5-32-545",
		},
		control: harness.controlOriginal, execution: harness.executionOriginal,
	}
	harness.filesystem = &fakeLifecycleTransaction{harness: harness, name: "filesystem"}
	harness.root = &fakeRootTransaction{harness: harness, layout: layout}
	harness.service = &fakeLifecycleTransaction{harness: harness, name: "service"}
	harness.runnerStorage = &fakeRunnerStorageTransaction{harness: harness}
	harness.registration = &fakeLifecycleTransaction{harness: harness, name: "registration"}
	harness.runnerService = &fakeLifecycleTransaction{harness: harness, name: "runner-service"}
	return harness
}

func (harness *transactionHarness) dependencies() dependencies {
	return dependencies{
		preflightService: func() error {
			harness.operations = append(harness.operations, "service-preflight")
			return harness.failures["service-preflight"]
		},
		preflightRunnerService: func() error {
			harness.operations = append(harness.operations, "runner-service-preflight")
			return harness.failures["runner-service-preflight"]
		},
		accounts: func(context.Context, installplan.Spec) (accountTransaction, error) {
			harness.operations = append(harness.operations, "accounts-provision")
			if err := harness.failures["accounts-provision"]; err != nil {
				return nil, err
			}
			return harness.account, nil
		},
		filesystem: func(context.Context, installconfig.Config) (filesystemTransaction, error) {
			harness.operations = append(harness.operations, "filesystem-provision")
			if err := harness.failures["filesystem-provision"]; err != nil {
				return nil, err
			}
			return harness.filesystem, nil
		},
		root: func(context.Context, string) (rootTransaction, error) {
			harness.operations = append(harness.operations, "root-provision")
			if err := harness.failures["root-provision"]; err != nil {
				return nil, err
			}
			return harness.root, nil
		},
		materialize: func(
			ctx context.Context,
			specification installplan.Spec,
			binding installplan.IdentityBinding,
			password []byte,
			store sharedstate.Store,
		) (sharedstate.Receipt, error) {
			harness.operations = append(harness.operations, "state-materialize")
			if err := harness.failures["state-materialize"]; err != nil {
				return sharedstate.Receipt{}, err
			}
			receipt, err := sharedstate.Materialize(
				ctx, specification, binding, password, store, fakeSealer{harness: harness},
			)
			if harness.badReceipt {
				receipt.ConfigWritten = false
			}
			return receipt, err
		},
		service: func(context.Context, string) (serviceTransaction, error) {
			harness.operations = append(harness.operations, "service-provision")
			if harness.onService != nil {
				harness.onService()
			}
			if err := harness.failures["service-provision"]; err != nil {
				return nil, err
			}
			return harness.service, nil
		},
		runnerStorage: func(context.Context, string, string, string, *runnerpackage.Image) (runnerStorageTransaction, error) {
			harness.operations = append(harness.operations, "runner-storage-provision")
			if err := harness.failures["runner-storage-provision"]; err != nil {
				return nil, err
			}
			return harness.runnerStorage, nil
		},
		runnerRegistration: func(context.Context, string, runnerregistration.Request, runnerStorageTransaction) (serviceTransaction, error) {
			harness.operations = append(harness.operations, "runner-registration-provision")
			if err := harness.failures["runner-registration-provision"]; err != nil {
				return nil, err
			}
			return harness.registration, nil
		},
		runnerService: func(_ context.Context, _ string, _ string, password []byte, _ runnerStorageTransaction) (serviceTransaction, error) {
			harness.operations = append(harness.operations, "runner-service-provision")
			if !bytes.Equal(password, harness.controlOriginal) {
				return nil, errors.New("unexpected control password")
			}
			if err := harness.failures["runner-service-provision"]; err != nil {
				return nil, err
			}
			return harness.runnerService, nil
		},
	}
}

func (transaction *fakeAccountTransaction) IdentityBinding() installplan.IdentityBinding {
	return transaction.binding
}

func (transaction *fakeAccountTransaction) ControlPassword() []byte {
	return transaction.control
}

func (transaction *fakeAccountTransaction) ExecutionPassword() []byte {
	return transaction.execution
}

func (transaction *fakeAccountTransaction) ClearExecutionPassword() error {
	transaction.harness.operations = append(transaction.harness.operations, "execution-password-clear")
	if err := transaction.harness.failures["execution-password-clear"]; err != nil {
		return err
	}
	zeroBytes(transaction.execution)
	transaction.execution = nil
	return nil
}

func (transaction *fakeAccountTransaction) Commit() error {
	transaction.harness.operations = append(transaction.harness.operations, "accounts-commit")
	zeroBytes(transaction.control)
	zeroBytes(transaction.execution)
	transaction.control = nil
	transaction.execution = nil
	return transaction.harness.failures["accounts-commit"]
}

func (transaction *fakeAccountTransaction) Close() error {
	transaction.harness.operations = append(transaction.harness.operations, "accounts-close")
	zeroBytes(transaction.control)
	zeroBytes(transaction.execution)
	transaction.control = nil
	transaction.execution = nil
	return transaction.harness.failures["accounts-close"]
}

func (transaction *fakeLifecycleTransaction) Commit() error {
	transaction.harness.operations = append(transaction.harness.operations, transaction.name+"-commit")
	return transaction.harness.failures[transaction.name+"-commit"]
}

func (transaction *fakeLifecycleTransaction) Close() error {
	transaction.harness.operations = append(transaction.harness.operations, transaction.name+"-close")
	return transaction.harness.failures[transaction.name+"-close"]
}

func (transaction *fakeRootTransaction) EnsureProtectedDirectory(path string) error {
	transaction.harness.operations = append(transaction.harness.operations, "directory-verify:"+path)
	return transaction.harness.failures["directory-verify"]
}

func (transaction *fakeRootTransaction) WriteProtectedFile(path string, _ []byte) error {
	transaction.harness.operations = append(transaction.harness.operations, "state-write:"+path)
	return transaction.harness.failures["state-write"]
}

func (transaction *fakeRootTransaction) InstallationLayout() (installplan.Layout, error) {
	transaction.harness.operations = append(transaction.harness.operations, "layout-verify")
	return transaction.layout, transaction.harness.failures["layout-verify"]
}

func (transaction *fakeRootTransaction) WriteBrokerImage(context.Context, []byte) error {
	transaction.harness.operations = append(transaction.harness.operations, "broker-image-write")
	return transaction.harness.failures["broker-image-write"]
}

func (transaction *fakeRootTransaction) WriteControlImage(context.Context, []byte) error {
	transaction.harness.operations = append(transaction.harness.operations, "control-image-write")
	return transaction.harness.failures["control-image-write"]
}

func (transaction *fakeRootTransaction) Commit() error {
	transaction.harness.operations = append(transaction.harness.operations, "root-commit")
	return transaction.harness.failures["root-commit"]
}

func (transaction *fakeRootTransaction) Close() error {
	transaction.harness.operations = append(transaction.harness.operations, "root-close")
	return transaction.harness.failures["root-close"]
}

func (transaction *fakeRunnerStorageTransaction) SealGeneratedState(context.Context) error {
	return nil
}

func (transaction *fakeRunnerStorageTransaction) VerifyRegistrationState(context.Context) error {
	return nil
}

func (transaction *fakeRunnerStorageTransaction) VerifyServiceExecutable(context.Context) error {
	return nil
}

func (transaction *fakeRunnerStorageTransaction) Commit() error {
	transaction.harness.operations = append(transaction.harness.operations, "runner-storage-commit")
	return transaction.harness.failures["runner-storage-commit"]
}

func (transaction *fakeRunnerStorageTransaction) Close() error {
	transaction.harness.operations = append(transaction.harness.operations, "runner-storage-close")
	return transaction.harness.failures["runner-storage-close"]
}

func (sealer fakeSealer) Seal(password []byte) ([]byte, error) {
	sealer.harness.operations = append(sealer.harness.operations, "execution-password-seal")
	if !bytes.Equal(password, sealer.harness.executionOriginal) {
		return nil, errors.New("unexpected execution password")
	}
	return []byte("synthetic-protected-credential"), nil
}

func TestProvisionComposesTheExactVerifiedOrder(t *testing.T) {
	harness := newTransactionHarness(t)
	lease, err := provision(context.Background(), preparedInstallerInput(t), harness.dependencies())
	if err != nil {
		t.Fatal(err)
	}
	layout := harness.root.layout
	expected := []string{
		"service-preflight",
		"runner-service-preflight",
		"accounts-provision",
		"filesystem-provision",
		"root-provision",
		"broker-image-write",
		"control-image-write",
		"state-materialize",
		"directory-verify:" + layout.Root,
		"directory-verify:" + layout.BinDirectory,
		"directory-verify:" + layout.StateDirectory,
		"execution-password-seal",
		"state-write:" + layout.ExecutionCredential,
		"state-write:" + layout.InstallationConfig,
		"layout-verify",
		"execution-password-clear",
		"state-write:" + layout.InstallationMetadata,
		"service-provision",
		"runner-storage-provision",
		"runner-registration-provision",
		"runner-service-provision",
	}
	if !reflect.DeepEqual(harness.operations, expected) {
		t.Fatalf("unexpected installer stage order: %#v", harness.operations)
	}
	assertZeroBuffer(t, harness.executionOriginal)
	if len(harness.account.control) == 0 {
		t.Fatal("control password was cleared before runner-service consumption")
	}
	configuration, err := lease.Configuration()
	if err != nil {
		t.Fatal(err)
	}
	if configuration.ControlIdentity.Identifier != harness.account.binding.ControlIdentifier ||
		configuration.ExecutionIdentity.Identifier != harness.account.binding.ExecutionIdentifier {
		t.Fatal("composite lease did not retain the SID-bound installed configuration")
	}
	sourceSHA, err := lease.GatewaySourceSHA()
	if err != nil || sourceSHA != testSourceSHA {
		t.Fatal("composite lease did not retain the exact source SHA")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	expectedTail := []string{"runner-service-close", "registration-close", "runner-storage-close", "service-close", "root-close", "filesystem-close", "accounts-close"}
	actualTail := harness.operations[len(harness.operations)-len(expectedTail):]
	if !reflect.DeepEqual(actualTail, expectedTail) {
		t.Fatalf("composite rollback order differs: %#v", actualTail)
	}
	assertZeroBuffer(t, harness.controlOriginal)
}

func TestProvisionRollsBackEveryOwnedStageFailure(t *testing.T) {
	tests := []struct {
		stage  string
		rule   string
		closed []string
	}{
		{stage: "service-preflight", rule: "service-preflight-failed"},
		{stage: "runner-service-preflight", rule: "runner-service-preflight-failed"},
		{stage: "accounts-provision", rule: "account-provision-failed"},
		{stage: "filesystem-provision", rule: "filesystem-provision-failed", closed: []string{"accounts-close"}},
		{stage: "root-provision", rule: "installation-root-provision-failed", closed: []string{"filesystem-close", "accounts-close"}},
		{stage: "broker-image-write", rule: "broker-image-materialization-failed", closed: []string{"root-close", "filesystem-close", "accounts-close"}},
		{stage: "control-image-write", rule: "control-image-materialization-failed", closed: []string{"root-close", "filesystem-close", "accounts-close"}},
		{stage: "state-materialize", rule: "installation-state-materialization-failed", closed: []string{"root-close", "filesystem-close", "accounts-close"}},
		{stage: "execution-password-clear", rule: "execution-password-clear-failed", closed: []string{"root-close", "filesystem-close", "accounts-close"}},
		{stage: "service-provision", rule: "service-provision-failed", closed: []string{"root-close", "filesystem-close", "accounts-close"}},
		{stage: "runner-storage-provision", rule: "runner-storage-provision-failed", closed: []string{"service-close", "root-close", "filesystem-close", "accounts-close"}},
		{stage: "runner-registration-provision", rule: "runner-registration-failed", closed: []string{"runner-storage-close", "service-close", "root-close", "filesystem-close", "accounts-close"}},
		{stage: "runner-service-provision", rule: "runner-service-provision-failed", closed: []string{"registration-close", "runner-storage-close", "service-close", "root-close", "filesystem-close", "accounts-close"}},
	}
	for _, test := range tests {
		t.Run(test.stage, func(t *testing.T) {
			harness := newTransactionHarness(t)
			harness.failures[test.stage] = errors.New("synthetic stage failure")
			lease, err := provision(context.Background(), preparedInstallerInput(t), harness.dependencies())
			if lease != nil {
				t.Fatal("failed installer stage produced a lease")
			}
			assertInstallerRule(t, err, test.rule)
			for _, operation := range test.closed {
				if !containsInstallerOperation(harness.operations, operation) {
					t.Fatalf("owned stage was not rolled back: %s / %#v", operation, harness.operations)
				}
			}
			if len(test.closed) > 0 {
				assertZeroBuffer(t, harness.controlOriginal)
				assertZeroBuffer(t, harness.executionOriginal)
			}
		})
	}
}

func TestProvisionRejectsIncompleteMaterializationReceipt(t *testing.T) {
	harness := newTransactionHarness(t)
	harness.badReceipt = true
	lease, err := provision(context.Background(), preparedInstallerInput(t), harness.dependencies())
	if lease != nil {
		t.Fatal("unverified state receipt produced a lease")
	}
	assertInstallerRule(t, err, "installation-state-verification-failed")
	for _, operation := range []string{"root-close", "filesystem-close", "accounts-close"} {
		if !containsInstallerOperation(harness.operations, operation) {
			t.Fatalf("receipt failure did not roll back %s", operation)
		}
	}
}

func TestCancellationAfterServiceCreationRollsBackEverything(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	harness := newTransactionHarness(t)
	harness.onService = cancel
	lease, err := provision(ctx, preparedInstallerInput(t), harness.dependencies())
	if lease != nil {
		t.Fatal("cancelled installation produced a lease")
	}
	assertInstallerRule(t, err, "context-cancelled")
	expectedTail := []string{"service-close", "root-close", "filesystem-close", "accounts-close"}
	actualTail := harness.operations[len(harness.operations)-len(expectedTail):]
	if !reflect.DeepEqual(actualTail, expectedTail) {
		t.Fatalf("post-service cancellation rollback order differs: %#v", actualTail)
	}
}

func TestCommitFinalizesServiceFirstAndClearsControlCredential(t *testing.T) {
	harness := newTransactionHarness(t)
	lease, err := provision(context.Background(), preparedInstallerInput(t), harness.dependencies())
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Commit(); err != nil {
		t.Fatal(err)
	}
	expectedTail := []string{"runner-service-commit", "service-commit", "registration-commit", "runner-storage-commit", "accounts-commit", "filesystem-commit", "root-commit"}
	actualTail := harness.operations[len(harness.operations)-len(expectedTail):]
	if !reflect.DeepEqual(actualTail, expectedTail) {
		t.Fatalf("commit order differs: %#v", actualTail)
	}
	assertZeroBuffer(t, harness.controlOriginal)
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if containsInstallerOperation(harness.operations, "service-close") {
		t.Fatal("committed service was rolled back")
	}
}

func TestServiceCommitFailureRollsBackAllOwnedStages(t *testing.T) {
	harness := newTransactionHarness(t)
	harness.failures["service-commit"] = errors.New("synthetic commit failure")
	lease, err := provision(context.Background(), preparedInstallerInput(t), harness.dependencies())
	if err != nil {
		t.Fatal(err)
	}
	assertInstallerRule(t, lease.Commit(), "service-commit-failed")
	expectedTail := []string{
		"runner-service-commit", "service-commit", "registration-close", "runner-storage-close",
		"service-close", "root-close", "filesystem-close", "accounts-close",
	}
	actualTail := harness.operations[len(harness.operations)-len(expectedTail):]
	if !reflect.DeepEqual(actualTail, expectedTail) {
		t.Fatalf("failed commit rollback order differs: %#v", actualTail)
	}
	assertZeroBuffer(t, harness.controlOriginal)
}

func TestCommitReportsRollbackFailureAfterAttemptingAllCleanup(t *testing.T) {
	harness := newTransactionHarness(t)
	harness.failures["service-commit"] = errors.New("synthetic commit failure")
	harness.failures["service-close"] = errors.New("synthetic rollback failure")
	lease, err := provision(context.Background(), preparedInstallerInput(t), harness.dependencies())
	if err != nil {
		t.Fatal(err)
	}
	assertInstallerRule(t, lease.Commit(), "commit-rollback-failed")
	for _, operation := range []string{"root-close", "filesystem-close", "accounts-close"} {
		if !containsInstallerOperation(harness.operations, operation) {
			t.Fatalf("rollback failure stopped later cleanup: %s", operation)
		}
	}
}

func TestCommitAttemptsEveryInfallibleFinalizer(t *testing.T) {
	harness := newTransactionHarness(t)
	harness.failures["filesystem-commit"] = errors.New("synthetic invariant failure")
	lease, err := provision(context.Background(), preparedInstallerInput(t), harness.dependencies())
	if err != nil {
		t.Fatal(err)
	}
	assertInstallerRule(t, lease.Commit(), "commit-finalization-failed")
	for _, operation := range []string{"service-commit", "accounts-commit", "filesystem-commit", "root-commit"} {
		if !containsInstallerOperation(harness.operations, operation) {
			t.Fatalf("finalization stopped early: %s", operation)
		}
	}
	assertZeroBuffer(t, harness.controlOriginal)
}

func TestProvisionRequiresEveryDependencyBeforeMutation(t *testing.T) {
	harness := newTransactionHarness(t)
	deps := harness.dependencies()
	deps.service = nil
	lease, err := provision(context.Background(), preparedInstallerInput(t), deps)
	if lease != nil {
		t.Fatal("incomplete dependencies produced a lease")
	}
	assertInstallerRule(t, err, "dependency-required")
	if len(harness.operations) != 0 {
		t.Fatal("incomplete dependencies reached a mutation stage")
	}
}

func preparedInstallerInput(t *testing.T) preparedInput {
	t.Helper()
	prepared, err := prepareInputWithPolicy(Input{
		Specification: installerSpec(), GatewaySourceSHA: testSourceSHA,
		BrokerImage: syntheticBrokerImage(testSourceSHA), ControlImage: syntheticBrokerImage(testSourceSHA), RunnerImage: syntheticRunnerImage(t),
		RunnerRegistration: syntheticRunnerRegistration(t),
		Metadata:           syntheticMetadata(),
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func syntheticMetadata() installmetadata.Metadata {
	return installmetadata.Metadata{
		MetadataVersion: installmetadata.Version, Platform: platformpath.Windows,
		InstallationRoot: installerSpec().InstallationRoot, ControlRepository: "example/control-plane",
		RunnerName: "workstation-1", GatewaySourceSHA: testSourceSHA,
		ControlFiles: []installmetadata.ControlFile{
			{Path: ".github/workflows/execute-request.yml", SHA256: strings.Repeat("1", 64), Owned: true},
			{Path: "control-version.json", SHA256: strings.Repeat("2", 64), Owned: true},
		},
	}
}

func syntheticRunnerImage(t *testing.T) *runnerpackage.Image {
	t.Helper()
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for _, name := range []string{"bin/Runner.Listener.exe", "bin/RunnerService.exe"} {
		file, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte("synthetic runner image")); err != nil {
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

func syntheticRunnerRegistration(t *testing.T) runnerregistration.Request {
	t.Helper()
	repository, err := runnerregistration.VerifyPrivateRepository("example/control-plane", true)
	if err != nil {
		t.Fatal(err)
	}
	return runnerregistration.Request{
		Repository: repository, RunnerName: "workstation-1",
		RegistrationToken: []byte("synthetic-registration-token-1"),
		RemovalToken:      []byte("synthetic-removal-token-2"),
	}
}

func containsInstallerOperation(operations []string, expected string) bool {
	for _, operation := range operations {
		if operation == expected {
			return true
		}
	}
	return false
}

func assertZeroBuffer(t *testing.T, buffer []byte) {
	t.Helper()
	for _, value := range buffer {
		if value != 0 {
			t.Fatal("credential buffer was not cleared")
		}
	}
}
