//go:build linux

package pathresolver

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionpolicy"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

type Resolver struct{}

type Error struct{ Rule string }

func (failure *Error) Error() string {
	return fmt.Sprintf("Linux path resolution failed: %s", failure.Rule)
}

func (Resolver) ResolveWithin(ctx context.Context, platform platformpath.Platform, requested string, roots []string) (executionpolicy.Resolution, error) {
	if ctx == nil || platform != platformpath.Linux || platformpath.ValidateAbsolute(platform, requested) != nil || len(roots) == 0 {
		return executionpolicy.Resolution{}, resolverError("input-invalid")
	}
	if err := ctx.Err(); err != nil {
		return executionpolicy.Resolution{}, resolverError("cancelled")
	}
	working, err := canonicalDirectory(requested)
	if err != nil {
		return executionpolicy.Resolution{}, resolverError("working-directory-invalid")
	}
	for _, configured := range roots {
		if platformpath.ValidateAbsolute(platform, configured) != nil {
			return executionpolicy.Resolution{}, resolverError("approved-root-invalid")
		}
		root, err := canonicalDirectory(configured)
		if err != nil || root != configured {
			continue
		}
		if platformpath.Contains(platform, root, working) {
			return executionpolicy.Resolution{RequestedPath: requested, WorkingDirectory: working, ApprovedRoot: configured}, nil
		}
	}
	return executionpolicy.Resolution{}, resolverError("outside-approved-root")
}

func canonicalDirectory(candidate string) (string, error) {
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil || platformpath.ValidateAbsolute(platformpath.Linux, resolved) != nil {
		return "", resolverError("symlink-resolution-failed")
	}
	fd, err := unix.Open(resolved, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", resolverError("directory-open-failed")
	}
	defer unix.Close(fd)
	stable, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil || stable != resolved {
		return "", resolverError("directory-changed")
	}
	return resolved, nil
}

func resolverError(rule string) error { return &Error{Rule: rule} }

var _ executionpolicy.Resolver = Resolver{}
