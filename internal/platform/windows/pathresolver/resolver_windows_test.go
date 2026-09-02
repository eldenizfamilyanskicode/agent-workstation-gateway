//go:build windows

package pathresolver

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

func TestResolverUsesNativeDirectoryPathsWithinRoot(t *testing.T) {
	root := canonicalTestPath(t, t.TempDir())
	workingDirectory := filepath.Join(root, "demo")
	if err := os.Mkdir(workingDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	resolution, err := (Resolver{}).ResolveWithin(context.Background(), platformpath.Windows, workingDirectory, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	if resolution.RequestedPath != workingDirectory || !platformpath.Equal(platformpath.Windows, resolution.WorkingDirectory, workingDirectory) || resolution.ApprovedRoot != root {
		t.Fatalf("unexpected resolution: %#v", resolution)
	}
}

func TestResolverRejectsOutsideMissingAndFilePathsWithoutEcho(t *testing.T) {
	root := canonicalTestPath(t, t.TempDir())
	outside := canonicalTestPath(t, t.TempDir())
	filePath := filepath.Join(root, "SYNTHETIC-REJECTED-PATH-51e8.txt")
	if err := os.WriteFile(filePath, []byte("synthetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		requested string
		rule      string
	}{
		{name: "outside", requested: outside, rule: "outside-approved-root"},
		{name: "missing", requested: filepath.Join(root, "missing"), rule: "request-resolution-failed"},
		{name: "file", requested: filePath, rule: "request-resolution-failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := (Resolver{}).ResolveWithin(context.Background(), platformpath.Windows, test.requested, []string{root})
			assertResolverRule(t, err, test.rule)
			if strings.Contains(err.Error(), test.requested) || strings.Contains(err.Error(), "SYNTHETIC-REJECTED-PATH") {
				t.Fatal("resolver error echoed rejected path data")
			}
		})
	}
}

func TestResolverRejectsRealLinkEscapeAndRootAlias(t *testing.T) {
	root := canonicalTestPath(t, t.TempDir())
	outside := canonicalTestPath(t, t.TempDir())
	escape := filepath.Join(root, "escape")
	createDirectoryLink(t, outside, escape)
	_, err := (Resolver{}).ResolveWithin(context.Background(), platformpath.Windows, escape, []string{root})
	assertResolverRule(t, err, "outside-approved-root")

	realRoot := canonicalTestPath(t, t.TempDir())
	workingDirectory := filepath.Join(realRoot, "demo")
	if err := os.Mkdir(workingDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	aliasParent := canonicalTestPath(t, t.TempDir())
	rootAlias := filepath.Join(aliasParent, "root-alias")
	createDirectoryLink(t, realRoot, rootAlias)
	_, err = (Resolver{}).ResolveWithin(context.Background(), platformpath.Windows, filepath.Join(rootAlias, "demo"), []string{rootAlias})
	assertResolverRule(t, err, "approved-root-alias-rejected")
}

func TestResolverRejectsCancelledAndWrongPlatform(t *testing.T) {
	root := canonicalTestPath(t, t.TempDir())
	_, err := (Resolver{}).ResolveWithin(nil, platformpath.Windows, root, []string{root})
	assertResolverRule(t, err, "context-required")
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = (Resolver{}).ResolveWithin(cancelled, platformpath.Windows, root, []string{root})
	assertResolverRule(t, err, "context-cancelled")
	_, err = (Resolver{}).ResolveWithin(context.Background(), platformpath.Linux, root, []string{root})
	assertResolverRule(t, err, "platform-mismatch")
}

func createDirectoryLink(t *testing.T, target string, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err == nil {
		return
	}
	command := exec.Command("cmd.exe", "/D", "/Q", "/C", "mklink", "/J", link, target)
	if err := command.Run(); err != nil {
		t.Skip("this Windows host cannot create a test symbolic link or junction")
	}
}

func canonicalTestPath(t *testing.T, path string) string {
	t.Helper()
	absolute, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	absolute = filepath.Clean(absolute)
	if len(absolute) >= 2 && absolute[1] == ':' {
		absolute = strings.ToUpper(absolute[:1]) + absolute[1:]
	}
	if err := platformpath.ValidateAbsolute(platformpath.Windows, absolute); err != nil {
		t.Fatalf("test path is not canonical: %v", err)
	}
	return absolute
}

func assertResolverRule(t *testing.T, err error, rule string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected resolver rule %q", rule)
	}
	var resolverFailure *Error
	if !errors.As(err, &resolverFailure) || resolverFailure.Rule != rule {
		t.Fatalf("expected resolver rule %q, got %T / %v", rule, err, err)
	}
}
