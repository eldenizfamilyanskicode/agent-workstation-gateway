//go:build windows

package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionrun"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/process"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

const syntheticArtifactSID = "S-1-5-21-3000-3000-3000-4300"

type currentTokenSource struct{}

type testTokenLease struct {
	token windows.Token
}

func (currentTokenSource) Acquire(ctx context.Context, _ installconfig.Principal) (process.TokenLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var token windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &token,
	); err != nil {
		return nil, err
	}
	return &testTokenLease{token: token}, nil
}

func (lease *testTokenLease) Token() windows.Token { return lease.token }

func (lease *testTokenLease) Close() error {
	if lease.token == 0 {
		return nil
	}
	err := lease.token.Close()
	lease.token = 0
	return err
}

func TestCollectorStreamsStableRecursiveArtifacts(t *testing.T) {
	collector, plan := testCollector(t, []v1.ArtifactSelection{
		{Name: "results", Paths: []string{"reports/**/*.txt"}},
		{Name: "missing", Paths: []string{"missing/*.json"}},
	})
	contents := map[string]string{
		"reports/root.txt":       "root artifact\n",
		"reports/nested/one.txt": "nested artifact\n",
		"reports/ignored.json":   "{}\n",
	}
	for relative, content := range contents {
		writeTestFile(t, plan.WorkingDirectory, relative, content)
	}

	collection, err := collector.Collect(context.Background(), plan)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	defer collection.Bundle.Close()
	if collection.Manifest.Status != v1.ArtifactStatusCompleteWithOmissions || len(collection.Manifest.Files) != 2 {
		t.Fatalf("unexpected manifest: %#v", collection.Manifest)
	}
	if len(collection.Manifest.Omissions) != 1 ||
		collection.Manifest.Omissions[0].Pattern != "missing/*.json" ||
		collection.Manifest.Omissions[0].Reason != v1.ArtifactOmissionNoMatch {
		t.Fatalf("unexpected omissions: %#v", collection.Manifest.Omissions)
	}
	paths := []string{collection.Manifest.Files[0].Path, collection.Manifest.Files[1].Path}
	if !sort.StringsAreSorted(paths) {
		t.Fatalf("artifact paths are not stable: %#v", paths)
	}
	for _, file := range collection.Manifest.Files {
		reader, err := collection.Bundle.Open(file.Group, file.Path)
		if err != nil {
			t.Fatalf("open %s: %v", file.Path, err)
		}
		actual, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("read %s: %v", file.Path, err)
		}
		if err := reader.Close(); err != nil {
			t.Fatalf("close %s: %v", file.Path, err)
		}
		expected := []byte(contents[file.Path])
		digest := sha256.Sum256(expected)
		if string(actual) != string(expected) || file.SizeBytes != int64(len(expected)) || file.SHA256 != hex.EncodeToString(digest[:]) {
			t.Fatalf("artifact metadata/content mismatch for %s: %#v / %q", file.Path, file, actual)
		}
	}
	if _, err := collection.Bundle.Open("results", "unselected.txt"); err == nil {
		t.Fatal("bundle opened an unselected path")
	}
}

func TestCollectorHoldsContentStableUntilBundleClose(t *testing.T) {
	collector, plan := testCollector(t, []v1.ArtifactSelection{{Name: "results", Paths: []string{"result.txt"}}})
	path := writeTestFile(t, plan.WorkingDirectory, "result.txt", "before\n")
	collection, err := collector.Collect(context.Background(), plan)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if err := os.WriteFile(path, []byte("during\n"), 0o600); err == nil {
		_ = collection.Bundle.Close()
		t.Fatal("retained artifact handle allowed concurrent replacement")
	}
	reader, err := collection.Bundle.Open("results", "result.txt")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := collection.Bundle.Open("results", "result.txt"); err == nil {
		t.Fatal("bundle allowed a second transfer of one handle")
	}
	if err := collection.Bundle.Close(); err != nil {
		t.Fatalf("bundle close: %v", err)
	}
	if _, err := io.ReadAll(reader); err == nil {
		t.Fatal("reader remained usable after bundle close")
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("reader close after bundle: %v", err)
	}
	if err := os.WriteFile(path, []byte("after\n"), 0o600); err != nil {
		t.Fatalf("bundle close did not release file: %v", err)
	}
	if _, err := collection.Bundle.Open("results", "result.txt"); err == nil {
		t.Fatal("closed bundle accepted open")
	}
}

func TestCollectorDoesNotTraverseSensitiveDirectory(t *testing.T) {
	collector, plan := testCollector(t, []v1.ArtifactSelection{{Name: "results", Paths: []string{"**/*.txt"}}})
	writeTestFile(t, plan.WorkingDirectory, "safe.txt", "safe\n")
	writeTestFile(t, plan.WorkingDirectory, ".git/hidden.txt", "not collected\n")
	collection, err := collector.Collect(context.Background(), plan)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	defer collection.Bundle.Close()
	if len(collection.Manifest.Files) != 1 || collection.Manifest.Files[0].Path != "safe.txt" {
		t.Fatalf("sensitive content crossed policy: %#v", collection.Manifest.Files)
	}
	if len(collection.Manifest.Omissions) != 1 || collection.Manifest.Omissions[0].Reason != v1.ArtifactOmissionPolicyRejected {
		t.Fatalf("sensitive traversal was not explicit: %#v", collection.Manifest.Omissions)
	}
}

func TestCollectorRejectsDirectoryReparseEscape(t *testing.T) {
	collector, plan := testCollector(t, []v1.ArtifactSelection{{Name: "results", Paths: []string{"linked/**/*.txt"}}})
	outside := t.TempDir()
	writeTestFile(t, outside, "secret.txt", "outside\n")
	link := filepath.Join(plan.WorkingDirectory, "linked")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("directory symlink unavailable: %v", err)
	}
	collection, err := collector.Collect(context.Background(), plan)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if collection.Bundle != nil || len(collection.Manifest.Files) != 0 || len(collection.Manifest.Omissions) != 1 ||
		collection.Manifest.Omissions[0].Reason != v1.ArtifactOmissionLinkRejected {
		t.Fatalf("reparse escape was not rejected: %#v", collection)
	}
}

func TestCollectorRejectsHardLinkedArtifact(t *testing.T) {
	collector, plan := testCollector(t, []v1.ArtifactSelection{{Name: "results", Paths: []string{"linked.txt"}}})
	source := filepath.Join(plan.ApprovedRoot, "outside.txt")
	if err := os.WriteFile(source, []byte("outside working directory\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if err := os.Link(source, filepath.Join(plan.WorkingDirectory, "linked.txt")); err != nil {
		t.Skipf("hard link unavailable: %v", err)
	}
	collection, err := collector.Collect(context.Background(), plan)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if collection.Bundle != nil || len(collection.Manifest.Files) != 0 || len(collection.Manifest.Omissions) != 1 ||
		collection.Manifest.Omissions[0].Reason != v1.ArtifactOmissionLinkRejected {
		t.Fatalf("hard link was not rejected: %#v", collection)
	}
}

func TestCollectorEnforcesFileAndByteLimitsBeforePublication(t *testing.T) {
	t.Run("file count", func(t *testing.T) {
		collector, plan := testCollector(t, []v1.ArtifactSelection{{Name: "results", Paths: []string{"*.txt"}}})
		for index := 0; index < v1.MaxArtifactFiles+1; index++ {
			name := filepath.Join(plan.WorkingDirectory, "file-"+leftPad(index)+".txt")
			if err := os.WriteFile(name, nil, 0o600); err != nil {
				t.Fatalf("write file %d: %v", index, err)
			}
		}
		collection, err := collector.Collect(context.Background(), plan)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		defer collection.Bundle.Close()
		if len(collection.Manifest.Files) != v1.MaxArtifactFiles || len(collection.Manifest.Omissions) != 1 ||
			collection.Manifest.Omissions[0].Reason != v1.ArtifactOmissionFileLimit {
			t.Fatalf("file limit not represented: files=%d omissions=%#v", len(collection.Manifest.Files), collection.Manifest.Omissions)
		}
	})
	t.Run("per-file bytes", func(t *testing.T) {
		collector, plan := testCollector(t, []v1.ArtifactSelection{{Name: "results", Paths: []string{"large.bin"}}})
		path := filepath.Join(plan.WorkingDirectory, "large.bin")
		file, err := os.Create(path)
		if err != nil {
			t.Fatalf("create sparse file: %v", err)
		}
		if err := file.Truncate(v1.MaxArtifactFileBytes + 1); err != nil {
			_ = file.Close()
			t.Fatalf("truncate sparse file: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close sparse file: %v", err)
		}
		collection, err := collector.Collect(context.Background(), plan)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		if collection.Bundle != nil || len(collection.Manifest.Files) != 0 || len(collection.Manifest.Omissions) != 1 ||
			collection.Manifest.Omissions[0].Reason != v1.ArtifactOmissionByteLimit {
			t.Fatalf("byte limit not represented: %#v", collection)
		}
	})
	t.Run("remaining total bytes", func(t *testing.T) {
		collector, plan := testCollector(t, []v1.ArtifactSelection{{Name: "results", Paths: []string{"small.bin"}}})
		_ = collector
		path := writeTestFile(t, plan.WorkingDirectory, "small.bin", "bounded\n")
		file, _, _, reason := openStableFile(context.Background(), path, plan.WorkingDirectory, plan.ApprovedRoot, 0)
		if file != nil {
			_ = file.Close()
		}
		if reason != v1.ArtifactOmissionByteLimit {
			t.Fatalf("remaining total limit not enforced before hashing: %s", reason)
		}
	})
}

func TestCollectorEnforcesTraversalDepth(t *testing.T) {
	collector, plan := testCollector(t, []v1.ArtifactSelection{{Name: "results", Paths: []string{"**/*.txt"}}})
	relative := ""
	for index := 0; index < maxArtifactDepth; index++ {
		relative += "level/"
	}
	writeTestFile(t, plan.WorkingDirectory, relative+"too-deep.txt", "not collected\n")
	collection, err := collector.Collect(context.Background(), plan)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if collection.Bundle != nil || len(collection.Manifest.Files) != 0 || len(collection.Manifest.Omissions) != 1 ||
		collection.Manifest.Omissions[0].Reason != v1.ArtifactOmissionPolicyRejected {
		t.Fatalf("depth limit not represented: %#v", collection)
	}
}

func TestCollectorRejectsCanceledAndMismatchedTokenPlans(t *testing.T) {
	collector, plan := testCollector(t, []v1.ArtifactSelection{{Name: "results", Paths: []string{"*.txt"}}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if collection, err := collector.Collect(ctx, plan); err == nil || collection.Bundle != nil {
		t.Fatalf("canceled collection admitted: %#v / %v", collection, err)
	}

	configuration := collector.configuration
	mismatchedSID := "S-1-5-21-3000-3000-3000-4301"
	if configuration.ControlIdentity.Identifier == mismatchedSID {
		mismatchedSID = "S-1-5-21-3000-3000-3000-4302"
	}
	configuration.ExecutionIdentity = installconfig.Principal{
		Name: "awg-exec", Identifier: mismatchedSID, PrimaryGroupIdentifier: "S-1-5-32-545",
	}
	mismatch, err := New(configuration, currentTokenSource{})
	if err != nil {
		t.Fatalf("mismatch collector: %v", err)
	}
	plan.ExecutionIdentity = configuration.ExecutionIdentity
	_, err = mismatch.Collect(context.Background(), plan)
	var failure *Error
	if !errors.As(err, &failure) || failure.Rule != "execution-token-identity-mismatch" {
		t.Fatalf("unexpected token mismatch result: %v", err)
	}
}

func testCollector(t *testing.T, selections []v1.ArtifactSelection) (*Collector, executionrun.ArtifactPlan) {
	t.Helper()
	rawRoot := t.TempDir()
	rootHandle, root, err := openVerifiedDirectory(rawRoot)
	if err != nil {
		t.Fatalf("resolve temporary root: %v", err)
	}
	if err := windows.CloseHandle(rootHandle); err != nil {
		t.Fatalf("close temporary root handle: %v", err)
	}
	working := filepath.Join(root, "work")
	if err := os.Mkdir(working, 0o700); err != nil {
		t.Fatalf("mkdir working: %v", err)
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("current user: %v", err)
	}
	primary, err := token.GetTokenPrimaryGroup()
	if err != nil || primary == nil || primary.PrimaryGroup == nil {
		t.Fatalf("current primary group: %v", err)
	}
	identifier := user.User.Sid.String()
	if !strings.HasPrefix(identifier, "S-1-5-21-") {
		t.Skipf("current test identity is not an account SID: %s", identifier)
	}
	control := syntheticArtifactSID
	if identifier == control {
		control = "S-1-5-21-3000-3000-3000-4301"
	}
	configuration := installconfig.Config{
		ConfigVersion: installconfig.CurrentVersion,
		Platform:      platformpath.Windows,
		ControlIdentity: installconfig.Principal{
			Name: "awg-control", Identifier: control, PrimaryGroupIdentifier: "S-1-5-32-545",
		},
		ExecutionIdentity: installconfig.Principal{
			Name: "awg-exec", Identifier: identifier, PrimaryGroupIdentifier: primary.PrimaryGroup.String(),
		},
		ApprovedRoots: []string{root},
		Shells: []installconfig.ShellBinding{{
			Shell: v1.ShellPowerShell, Executable: `C:\Program Files\PowerShell\7\pwsh.exe`,
		}},
		ProfileRoot:  `C:\ProgramData\AgentWorkstationGateway\test-profile`,
		TempRoot:     `C:\ProgramData\AgentWorkstationGateway\test-temp`,
		PathEntries:  []string{`C:\Program Files\PowerShell\7`},
		Capabilities: []installconfig.Capability{},
	}
	collector, err := New(configuration, currentTokenSource{})
	if err != nil {
		t.Fatalf("new collector: %v", err)
	}
	return collector, executionrun.ArtifactPlan{
		ExecutionIdentity: configuration.ExecutionIdentity,
		WorkingDirectory:  working,
		ApprovedRoot:      root,
		Selections:        selections,
	}
}

func writeTestFile(t *testing.T, root string, relative string, content string) string {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", relative, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", relative, err)
	}
	return path
}

func leftPad(value int) string {
	text := string(rune('0' + value%10))
	value /= 10
	text = string(rune('0'+value%10)) + text
	value /= 10
	return string(rune('0'+value%10)) + text
}
