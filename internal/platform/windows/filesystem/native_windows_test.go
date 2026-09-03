//go:build windows

package filesystem

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

const syntheticExecutionSID = "S-1-5-21-2000-2000-2000-4242"

func TestIsolatedDescriptorHasOnlyFixedReadersAndNoACLManagement(t *testing.T) {
	sid, err := windows.StringToSid(syntheticExecutionSID)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := isolatedDescriptor(sid)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateIsolatedDescriptor(descriptor, sid); err != nil {
		t.Fatal(err)
	}
	dacl, _, _ := descriptor.DACL()
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		ace, aceSID, err := aclEntry(dacl, index)
		if err != nil {
			t.Fatal(err)
		}
		if aceSID.Equals(sid) && ace.Mask&(windows.WRITE_DAC|windows.WRITE_OWNER) != 0 {
			t.Fatal("execution SID received ACL-management authority")
		}
	}
}

func TestNativeRejectsTargetsOutsideInstalledConfiguration(t *testing.T) {
	configuration, _, _, _ := temporaryConfiguration(t)
	native, err := New(configuration)
	if err != nil {
		t.Fatal(err)
	}
	_, err = native.ConvergeApprovedRoot(`C:\Users\Alice\Elsewhere`, syntheticExecutionSID)
	assertFilesystemError(t, err, "approved-root-not-installed")
	_, err = native.ConvergeIsolatedRoot(configuration.ProfileRoot, "S-1-5-21-2000-2000-2000-9999")
	assertFilesystemError(t, err, "isolated-root-not-installed")
}

func TestApprovedBaselineRejectsBroadACLManagement(t *testing.T) {
	sid, _ := windows.StringToSid(syntheticExecutionSID)
	descriptor, err := windows.SecurityDescriptorFromString("O:BAD:(A;;GA;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	_, err = validateApprovedBaseline(descriptor, sid)
	assertFilesystemError(t, err, "broad-principal-can-manage-acl")
}

func TestIsolatedDescriptorRejectsExtraExecutionRights(t *testing.T) {
	sid, _ := windows.StringToSid(syntheticExecutionSID)
	descriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf(
		"O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%s)", sid.String(),
	))
	if err != nil {
		t.Fatal(err)
	}
	assertFilesystemError(t, validateIsolatedDescriptor(descriptor, sid), "isolated-ace-mask-invalid")
}

func TestFailureCleanupOwnsChangeAfterNamedResultIsCleared(t *testing.T) {
	owned := &change{}
	result := (*change)(nil)
	resultErr := error(filesystemError("synthetic-failure"))
	rollbackFailedChange(owned, &result, &resultErr, "approved")()
	if !owned.discarded || result != nil {
		t.Fatal("failed change was not discarded independently of the named result")
	}
	assertFilesystemError(t, resultErr, "approved-failure-rollback-failed")
}

func TestDescriptorEquivalenceIgnoresOnlyAutoInheritanceControl(t *testing.T) {
	left, err := windows.SecurityDescriptorFromString("O:BAD:(A;OICI;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	right, err := windows.SecurityDescriptorFromString("O:BAD:AI(A;OICI;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	if !descriptorsEquivalent(left, right) {
		t.Fatal("equivalent ordered ACEs differed only by auto-inheritance bookkeeping")
	}
	different, err := windows.SecurityDescriptorFromString("O:BAD:AI(A;OICI;FR;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	if descriptorsEquivalent(left, different) {
		t.Fatal("descriptor equivalence ignored an access-mask change")
	}
}

func TestApprovedRootConvergenceAndRollbackUseOwnedHandle(t *testing.T) {
	configuration, approved, _, _ := temporaryConfiguration(t)
	native, err := New(configuration)
	if err != nil {
		t.Fatal(err)
	}
	before := descriptorForPath(t, approved)
	mutation, err := native.ConvergeApprovedRoot(approved, syntheticExecutionSID)
	if err != nil {
		t.Fatal(err)
	}
	owned, ok := mutation.(*change)
	if !ok || owned.handle == 0 {
		t.Fatal("native mutation did not retain its verified handle")
	}
	sid, _ := windows.StringToSid(syntheticExecutionSID)
	if err := validateApprovedApplied(descriptorForHandle(t, owned.handle), owned.original, sid, owned.originalProtected); err != nil {
		t.Fatal(err)
	}
	if err := mutation.Rollback(); err != nil {
		t.Fatal(err)
	}
	mutation.Discard()
	after := descriptorForPath(t, approved)
	if !descriptorsEquivalent(after, before) {
		t.Fatal("approved-root rollback did not restore the original descriptor")
	}
}

func TestNewIsolatedRootRollbackRemovesOnlyCreatedLeaf(t *testing.T) {
	configuration, _, profile, _ := temporaryConfiguration(t)
	native, err := New(configuration)
	if err != nil {
		t.Fatal(err)
	}
	mutation, err := native.ConvergeIsolatedRoot(profile, syntheticExecutionSID)
	if err != nil {
		t.Fatal(err)
	}
	owned := mutation.(*change)
	sid, _ := windows.StringToSid(syntheticExecutionSID)
	if !owned.created || validateIsolatedDescriptor(descriptorForHandle(t, owned.handle), sid) != nil {
		t.Fatal("new isolated root was not created with the fixed descriptor")
	}
	if err := mutation.Rollback(); err != nil {
		t.Fatal(err)
	}
	mutation.Discard()
	if _, err := os.Stat(profile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rollback retained the transaction-created isolated root")
	}
}

func TestIsolatedRootNeverAdoptsPreexistingDirectory(t *testing.T) {
	configuration, _, profile, _ := temporaryConfiguration(t)
	if err := os.Mkdir(profile, 0o700); err != nil {
		t.Fatal(err)
	}
	native, err := New(configuration)
	if err != nil {
		t.Fatal(err)
	}
	mutation, err := native.ConvergeIsolatedRoot(profile, syntheticExecutionSID)
	if mutation != nil {
		t.Fatal("preexisting isolated root produced a mutation lease")
	}
	assertFilesystemError(t, err, "isolated-directory-already-exists")
	if _, err := os.Stat(profile); err != nil {
		t.Fatal("preexisting isolated root was removed")
	}
}

func temporaryConfiguration(t *testing.T) (installconfig.Config, string, string, string) {
	t.Helper()
	base := canonicalDirectory(t, t.TempDir())
	approved := filepath.Join(base, "approved")
	if err := os.Mkdir(approved, 0o700); err != nil {
		t.Fatal(err)
	}
	approved = canonicalDirectory(t, approved)
	profile := filepath.Join(base, "profile")
	temporary := filepath.Join(base, "temporary")
	configuration := installconfig.Config{
		ConfigVersion: installconfig.CurrentVersion, Platform: platformpath.Windows,
		ControlIdentity:   installconfig.Principal{Name: "awg-control", Identifier: "S-1-5-21-2000-2000-2000-4241", PrimaryGroupIdentifier: "S-1-5-32-545"},
		ExecutionIdentity: installconfig.Principal{Name: "awg-exec", Identifier: syntheticExecutionSID, PrimaryGroupIdentifier: "S-1-5-32-545"},
		ApprovedRoots:     []string{approved},
		Shells:            []installconfig.ShellBinding{{Shell: v1.ShellPwsh, Executable: `C:\Program Files\PowerShell\7\pwsh.exe`}},
		ProfileRoot:       profile, TempRoot: temporary, PathEntries: []string{`C:\Windows\System32`},
		Capabilities: []installconfig.Capability{},
	}
	if err := installconfig.Validate(configuration); err != nil {
		t.Fatal(err)
	}
	return configuration, approved, profile, temporary
}

func canonicalDirectory(t *testing.T, path string) string {
	t.Helper()
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(
		pointer, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	canonical, err := finalPath(handle)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func descriptorForPath(t *testing.T, path string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	handle, err := openDirectory(path, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	return descriptorForHandle(t, handle)
}

func descriptorForHandle(t *testing.T, handle windows.Handle) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	descriptor, err := queryDescriptor(handle)
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}

func assertFilesystemError(t *testing.T, err error, rule string) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Rule != rule {
		t.Fatalf("expected %s, got %T / %v", rule, err, err)
	}
}
