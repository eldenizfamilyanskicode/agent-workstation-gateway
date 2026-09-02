//go:build windows

package pathresolver

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf16"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionpolicy"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

type Error struct {
	Rule string
}

func (failure *Error) Error() string {
	return fmt.Sprintf("Windows path resolution denied: %s", failure.Rule)
}

type Resolver struct{}

var _ executionpolicy.Resolver = Resolver{}

func (Resolver) ResolveWithin(
	ctx context.Context,
	platform platformpath.Platform,
	requested string,
	roots []string,
) (executionpolicy.Resolution, error) {
	if ctx == nil {
		return executionpolicy.Resolution{}, resolverError("context-required")
	}
	if platform != platformpath.Windows {
		return executionpolicy.Resolution{}, resolverError("platform-mismatch")
	}
	if err := platformpath.ValidateAbsolute(platformpath.Windows, requested); err != nil {
		return executionpolicy.Resolution{}, resolverError("invalid-request-path")
	}
	if len(roots) == 0 {
		return executionpolicy.Resolution{}, resolverError("approved-root-required")
	}

	resolvedRoots := make([]string, len(roots))
	for index, root := range roots {
		if err := contextError(ctx); err != nil {
			return executionpolicy.Resolution{}, err
		}
		if err := platformpath.ValidateAbsolute(platformpath.Windows, root); err != nil {
			return executionpolicy.Resolution{}, resolverError("invalid-approved-root")
		}
		resolvedRoot, err := resolveDirectory(root)
		if err != nil {
			return executionpolicy.Resolution{}, resolverError("approved-root-resolution-failed")
		}
		if !platformpath.Equal(platformpath.Windows, root, resolvedRoot) {
			return executionpolicy.Resolution{}, resolverError("approved-root-alias-rejected")
		}
		resolvedRoots[index] = resolvedRoot
	}

	if err := contextError(ctx); err != nil {
		return executionpolicy.Resolution{}, err
	}
	resolvedRequest, err := resolveDirectory(requested)
	if err != nil {
		return executionpolicy.Resolution{}, resolverError("request-resolution-failed")
	}
	for index, resolvedRoot := range resolvedRoots {
		if platformpath.Contains(platformpath.Windows, resolvedRoot, resolvedRequest) {
			return executionpolicy.Resolution{
				RequestedPath: requested, WorkingDirectory: resolvedRequest, ApprovedRoot: roots[index],
			}, nil
		}
	}
	return executionpolicy.Resolution{}, resolverError("outside-approved-root")
}

func resolveDirectory(path string) (string, error) {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	handle, err := windows.CreateFile(
		pathPointer,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)

	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return "", err
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return "", resolverError("not-directory")
	}
	finalPath, err := finalDOSPath(handle)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(finalPath, `\\?\UNC\`) {
		return "", resolverError("unc-path-not-supported")
	}
	finalPath = strings.TrimPrefix(finalPath, `\\?\`)
	if len(finalPath) >= 2 && finalPath[1] == ':' && finalPath[0] >= 'a' && finalPath[0] <= 'z' {
		finalPath = strings.ToUpper(finalPath[:1]) + finalPath[1:]
	}
	if err := platformpath.ValidateAbsolute(platformpath.Windows, finalPath); err != nil {
		return "", resolverError("non-canonical-final-path")
	}
	return finalPath, nil
}

func finalDOSPath(handle windows.Handle) (string, error) {
	buffer := make([]uint16, 512)
	for {
		length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
		if err != nil {
			return "", err
		}
		if length < uint32(len(buffer)) {
			return string(utf16.Decode(buffer[:length])), nil
		}
		buffer = make([]uint16, int(length)+1)
	}
}

func contextError(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return resolverError("context-cancelled")
	default:
		return nil
	}
}

func resolverError(rule string) error {
	return &Error{Rule: rule}
}
