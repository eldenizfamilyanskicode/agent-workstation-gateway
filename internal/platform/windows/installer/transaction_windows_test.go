//go:build windows

package installer

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	sharedstate "github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installstate"
)

type transactionHarness struct {
	operations        []string
	failures          map[string]error
	account           *fakeAccountTransaction
	filesystem        *fakeLifecycleTransaction
	root              *fakeRootTransaction
	service           *fakeLifecycleTransaction
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
	return harness
}

func (harness *transactionHarness) dependencies() dependencies {
	return dependencies{
		preflightService: func() error {
			harness.operations = append(harness.operations, "service-preflight")
			return harness.failures["service-preflight"]
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

func (transaction *fakeRootTransaction) Commit() error {
	transaction.harness.operations = append(transaction.harness.operations, "root-commit")
	return transaction.harness.failures["root-commit"]
}

func (transaction *fakeRootTransaction) Close() error {
	transaction.harness.operations = append(transaction.harness.operations, "root-close")
	return transaction.harness.failures["root-close"]
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
		"accounts-provision",
		"filesystem-provision",
		"root-provision",
		"broker-image-write",
		"state-materialize",
		"directory-verify:" + layout.Root,
		"directory-verify:" + layout.BinDirectory,
		"directory-verify:" + layout.StateDirectory,
		"execution-password-seal",
		"state-write:" + layout.ExecutionCredential,
		"state-write:" + layout.InstallationConfig,
		"layout-verify",
		"execution-password-clear",
		"service-provision",
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
	expectedTail := []string{"service-close", "root-close", "filesystem-close", "accounts-close"}
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
		{stage: "accounts-provision", rule: "account-provision-failed"},
		{stage: "filesystem-provision", rule: "filesystem-provision-failed", closed: []string{"accounts-close"}},
		{stage: "root-provision", rule: "installation-root-provision-failed", closed: []string{"filesystem-close", "accounts-close"}},
		{stage: "broker-image-write", rule: "broker-image-materialization-failed", closed: []string{"root-close", "filesystem-close", "accounts-close"}},
		{stage: "state-materialize", rule: "installation-state-materialization-failed", closed: []string{"root-close", "filesystem-close", "accounts-close"}},
		{stage: "execution-password-clear", rule: "execution-password-clear-failed", closed: []string{"root-close", "filesystem-close", "accounts-close"}},
		{stage: "service-provision", rule: "service-provision-failed", closed: []string{"root-close", "filesystem-close", "accounts-close"}},
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

func TestUseControlPasswordClearsOnlyTheTemporaryConsumerCopy(t *testing.T) {
	harness := newTransactionHarness(t)
	lease, err := provision(context.Background(), preparedInstallerInput(t), harness.dependencies())
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	var retained []byte
	if err := lease.UseControlPassword(func(password []byte) error {
		if !bytes.Equal(password, harness.controlOriginal) {
			t.Fatal("consumer did not receive the generated control password")
		}
		retained = password
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	assertZeroBuffer(t, retained)
	if len(harness.account.control) == 0 {
		t.Fatal("temporary consumer clearing removed the lease-owned credential")
	}
	retained = nil
	assertInstallerRule(t, lease.UseControlPassword(func(password []byte) error {
		retained = password
		return errors.New("synthetic consumer failure")
	}), "control-password-consumer-failed")
	assertZeroBuffer(t, retained)
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
	expectedTail := []string{"service-commit", "accounts-commit", "filesystem-commit", "root-commit"}
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
	expectedTail := []string{"service-commit", "service-close", "root-close", "filesystem-close", "accounts-close"}
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
	prepared, err := prepareInput(Input{
		Specification: installerSpec(), GatewaySourceSHA: testSourceSHA,
		BrokerImage: syntheticBrokerImage(testSourceSHA),
	})
	if err != nil {
		t.Fatal(err)
	}
	return prepared
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
