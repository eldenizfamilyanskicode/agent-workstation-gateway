//go:build windows

package installroot

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

const syntheticRoot = "C:\\ProgramData\\AgentWorkstationGateway"

type createResult struct {
	created bool
	err     error
}

type fakeRootBackend struct {
	operations []string
	creates    map[string]createResult
	failures   map[string]error
	onCreate   func(string)
}

func (backend *fakeRootBackend) CreateDirectory(path string) (bool, error) {
	key := "mkdir:" + path
	backend.operations = append(backend.operations, key)
	if backend.onCreate != nil {
		backend.onCreate(path)
	}
	return backend.create(key)
}

func (backend *fakeRootBackend) VerifyDirectory(path string) error {
	return backend.record("verify:" + path)
}

func (backend *fakeRootBackend) CreateStateFile(path string, _ []byte) (bool, error) {
	key := "state:" + path
	backend.operations = append(backend.operations, key)
	return backend.create(key)
}

func (backend *fakeRootBackend) CreateExecutable(path string, _ []byte) (bool, error) {
	key := "executable:" + path
	backend.operations = append(backend.operations, key)
	return backend.create(key)
}

func (backend *fakeRootBackend) RemoveStateFile(path string) error {
	return backend.record("remove-state:" + path)
}

func (backend *fakeRootBackend) RemoveExecutable(path string) error {
	return backend.record("remove-executable:" + path)
}

func (backend *fakeRootBackend) RemoveDirectory(path string) error {
	return backend.record("rmdir:" + path)
}

func (backend *fakeRootBackend) create(key string) (bool, error) {
	if result, ok := backend.creates[key]; ok {
		return result.created, result.err
	}
	return true, backend.failures[key]
}

func (backend *fakeRootBackend) record(key string) error {
	backend.operations = append(backend.operations, key)
	return backend.failures[key]
}

func TestProvisionCreatesOnlyTheFixedLayout(t *testing.T) {
	backend := &fakeRootBackend{}
	lease, err := provision(context.Background(), syntheticRoot, backend)
	if err != nil {
		t.Fatal(err)
	}
	layout, err := lease.InstallationLayout()
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"mkdir:" + layout.Root,
		"mkdir:" + layout.BinDirectory,
		"mkdir:" + layout.StateDirectory,
	}
	if !reflect.DeepEqual(backend.operations, expected) {
		t.Fatalf("unexpected protected layout operations: %#v", backend.operations)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	expected = append(expected,
		"rmdir:"+layout.StateDirectory,
		"rmdir:"+layout.BinDirectory,
		"rmdir:"+layout.Root,
	)
	if !reflect.DeepEqual(backend.operations, expected) {
		t.Fatalf("directories were not rolled back in reverse order: %#v", backend.operations)
	}
}

func TestProvisionNeverAdoptsAPreexistingRoot(t *testing.T) {
	backend := &fakeRootBackend{creates: map[string]createResult{
		"mkdir:" + syntheticRoot: {created: false, err: errors.New("synthetic collision")},
	}}
	lease, err := provision(context.Background(), syntheticRoot, backend)
	if lease != nil {
		t.Fatal("pre-existing root produced a lease")
	}
	assertRootRule(t, err, "installation-root-unavailable")
	if len(backend.operations) != 1 || backend.operations[0] != "mkdir:"+syntheticRoot {
		t.Fatalf("pre-existing root was adopted or removed: %#v", backend.operations)
	}
}

func TestProvisionRollsBackPartialDirectoryCreation(t *testing.T) {
	bin := syntheticRoot + "\\bin"
	backend := &fakeRootBackend{creates: map[string]createResult{
		"mkdir:" + bin: {created: true, err: errors.New("synthetic post-create failure")},
	}}
	lease, err := provision(context.Background(), syntheticRoot, backend)
	if lease != nil {
		t.Fatal("partial directory creation produced a lease")
	}
	assertRootRule(t, err, "protected-directory-create-failed")
	expected := []string{
		"mkdir:" + syntheticRoot, "mkdir:" + bin,
		"rmdir:" + bin, "rmdir:" + syntheticRoot,
	}
	if !reflect.DeepEqual(backend.operations, expected) {
		t.Fatalf("partial directories were not owned and reversed: %#v", backend.operations)
	}
}

func TestProvisionCancellationRollsBackCreatedDirectories(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	backend := &fakeRootBackend{onCreate: func(path string) {
		if path == syntheticRoot {
			cancel()
		}
	}}
	lease, err := provision(ctx, syntheticRoot, backend)
	if lease != nil {
		t.Fatal("cancelled root provisioning produced a lease")
	}
	assertRootRule(t, err, "context-cancelled")
	expected := []string{"mkdir:" + syntheticRoot, "rmdir:" + syntheticRoot}
	if !reflect.DeepEqual(backend.operations, expected) {
		t.Fatalf("cancelled root provisioning did not roll back: %#v", backend.operations)
	}
}

func TestLeaseRestrictsStoreToFixedOwnedPaths(t *testing.T) {
	backend := &fakeRootBackend{}
	lease, err := provision(context.Background(), syntheticRoot, backend)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	layout, _ := lease.InstallationLayout()
	for _, directory := range []string{layout.Root, layout.BinDirectory, layout.StateDirectory} {
		if err := lease.EnsureProtectedDirectory(directory); err != nil {
			t.Fatal(err)
		}
	}
	assertRootRule(t, lease.EnsureProtectedDirectory(syntheticRoot+"\\other"), "directory-not-owned")
	assertRootRule(t, lease.WriteProtectedFile(syntheticRoot+"\\other", []byte("state")), "state-path-not-owned")
}

func TestLeaseRollsBackOwnedFilesInReverseOrder(t *testing.T) {
	backend := &fakeRootBackend{}
	lease, err := provision(context.Background(), syntheticRoot, backend)
	if err != nil {
		t.Fatal(err)
	}
	layout, _ := lease.InstallationLayout()
	if err := lease.WriteBrokerImage(context.Background(), []byte("synthetic-broker-image")); err != nil {
		t.Fatal(err)
	}
	if err := lease.WriteControlImage(context.Background(), []byte("synthetic-control-image")); err != nil {
		t.Fatal(err)
	}
	if err := lease.WriteProtectedFile(layout.ExecutionCredential, []byte("synthetic-protected-credential")); err != nil {
		t.Fatal(err)
	}
	if err := lease.WriteProtectedFile(layout.InstallationConfig, []byte("synthetic-configuration")); err != nil {
		t.Fatal(err)
	}
	assertRootRule(t, lease.WriteProtectedFile(layout.InstallationConfig, []byte("again")), "state-path-already-attempted")
	assertRootRule(t, lease.WriteBrokerImage(context.Background(), []byte("again")), "broker-image-already-attempted")
	assertRootRule(t, lease.WriteControlImage(context.Background(), []byte("again")), "control-image-already-attempted")
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	expectedTail := []string{
		"remove-state:" + layout.InstallationConfig,
		"remove-state:" + layout.ExecutionCredential,
		"remove-executable:" + layout.ControlExecutable,
		"remove-executable:" + layout.BinDirectory + "\\awg-broker.exe",
		"rmdir:" + layout.StateDirectory,
		"rmdir:" + layout.BinDirectory,
		"rmdir:" + layout.Root,
	}
	actualTail := backend.operations[len(backend.operations)-len(expectedTail):]
	if !reflect.DeepEqual(actualTail, expectedTail) {
		t.Fatalf("owned files/directories were not reversed: %#v", actualTail)
	}
}

func TestLeaseTracksPostCreateFileFailure(t *testing.T) {
	backend := &fakeRootBackend{}
	lease, err := provision(context.Background(), syntheticRoot, backend)
	if err != nil {
		t.Fatal(err)
	}
	layout, _ := lease.InstallationLayout()
	key := "state:" + layout.ExecutionCredential
	backend.creates = map[string]createResult{
		key: {created: true, err: errors.New("synthetic post-create failure")},
	}
	assertRootRule(t, lease.WriteProtectedFile(layout.ExecutionCredential, []byte("synthetic")), "protected-state-create-failed")
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if !containsOperation(backend.operations, "remove-state:"+layout.ExecutionCredential) {
		t.Fatal("post-create failed state file was not rolled back")
	}
}

func TestLeaseCommitPreservesOwnedObjectsAndClosesMutation(t *testing.T) {
	backend := &fakeRootBackend{}
	lease, err := provision(context.Background(), syntheticRoot, backend)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.WriteBrokerImage(context.Background(), []byte("synthetic-broker-image")); err != nil {
		t.Fatal(err)
	}
	if err := lease.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	for _, operation := range backend.operations {
		if len(operation) >= 7 && (operation[:7] == "remove-" || operation[:6] == "rmdir:") {
			t.Fatalf("committed object was removed: %s", operation)
		}
	}
	assertRootRule(t, lease.WriteBrokerImage(context.Background(), []byte("after-commit")), "lease-closed")
}

func TestRollbackFailureIsReportedAfterAllCleanupAttempts(t *testing.T) {
	backend := &fakeRootBackend{}
	lease, err := provision(context.Background(), syntheticRoot, backend)
	if err != nil {
		t.Fatal(err)
	}
	layout, _ := lease.InstallationLayout()
	if err := lease.WriteBrokerImage(context.Background(), []byte("synthetic-broker-image")); err != nil {
		t.Fatal(err)
	}
	backend.failures = map[string]error{
		"remove-executable:" + layout.BinDirectory + "\\awg-broker.exe": errors.New("synthetic remove failure"),
	}
	assertRootRule(t, lease.Close(), "rollback-failed")
	if !containsOperation(backend.operations, "rmdir:"+layout.Root) {
		t.Fatal("rollback stopped before attempting the remaining owned directories")
	}
}

func containsOperation(operations []string, expected string) bool {
	for _, operation := range operations {
		if operation == expected {
			return true
		}
	}
	return false
}

func assertRootRule(t *testing.T, err error, rule string) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Rule != rule {
		t.Fatalf("expected %s, got %T / %v", rule, err, err)
	}
}
