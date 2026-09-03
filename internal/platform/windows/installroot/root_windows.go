//go:build windows

package installroot

import (
	"context"
	"fmt"
	"sync"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	sharedstate "github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installstate"
	winstate "github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/installstate"
)

type fileKind uint8

const (
	stateFile fileKind = iota + 1
	executableFile
)

type ownedFile struct {
	path string
	kind fileKind
}

type nativeBackend interface {
	CreateDirectory(string) (bool, error)
	VerifyDirectory(string) error
	CreateStateFile(string, []byte) (bool, error)
	CreateExecutable(string, []byte) (bool, error)
	RemoveStateFile(string) error
	RemoveExecutable(string) error
	RemoveDirectory(string) error
}

type windowsBackend struct {
	store winstate.NativeStore
}

type Lease struct {
	mu          sync.Mutex
	layout      installplan.Layout
	backend     nativeBackend
	directories []string
	files       []ownedFile
	attempted   map[string]bool
	committed   bool
	closed      bool
}

type Error struct {
	Rule string
}

func (failure *Error) Error() string {
	return fmt.Sprintf("Windows installation root failed: %s", failure.Rule)
}

func Provision(ctx context.Context, installationRoot string) (*Lease, error) {
	if ctx == nil {
		return nil, rootError("dependency-required")
	}
	if _, err := installplan.WindowsLayout(installationRoot); err != nil {
		return nil, rootError("installation-root-invalid")
	}
	return provision(ctx, installationRoot, &windowsBackend{})
}

func provision(
	ctx context.Context,
	installationRoot string,
	backend nativeBackend,
) (result *Lease, resultErr error) {
	if ctx == nil || backend == nil {
		return nil, rootError("dependency-required")
	}
	layout, err := installplan.WindowsLayout(installationRoot)
	if err != nil {
		return nil, rootError("installation-root-invalid")
	}
	lease := &Lease{layout: layout, backend: backend, attempted: make(map[string]bool)}
	failed := true
	defer func() {
		if failed {
			if rollbackErr := lease.Close(); rollbackErr != nil {
				result = nil
				resultErr = rootError("rollback-failed")
			}
		}
	}()
	for index, directory := range []string{layout.Root, layout.BinDirectory, layout.StateDirectory} {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		created, err := backend.CreateDirectory(directory)
		if created {
			lease.directories = append(lease.directories, directory)
		}
		if err != nil || !created {
			if index == 0 && !created {
				return nil, rootError("installation-root-unavailable")
			}
			return nil, rootError("protected-directory-create-failed")
		}
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	failed = false
	return lease, nil
}

// EnsureProtectedDirectory implements installstate.Store only for the three
// directories already created and owned by this lease.
func (lease *Lease) EnsureProtectedDirectory(path string) error {
	if lease == nil {
		return rootError("lease-invalid")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return rootError("lease-closed")
	}
	if !lease.fixedDirectory(path) {
		return rootError("directory-not-owned")
	}
	if err := lease.backend.VerifyDirectory(path); err != nil {
		return rootError("directory-verification-failed")
	}
	return nil
}

// WriteProtectedFile implements installstate.Store only for the fixed
// execution credential and installed configuration paths.
func (lease *Lease) WriteProtectedFile(path string, content []byte) error {
	if lease == nil {
		return rootError("lease-invalid")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return rootError("lease-closed")
	}
	if path != lease.layout.ExecutionCredential && path != lease.layout.InstallationConfig && path != lease.layout.InstallationMetadata {
		return rootError("state-path-not-owned")
	}
	if lease.attempted[path] {
		return rootError("state-path-already-attempted")
	}
	lease.attempted[path] = true
	created, err := lease.backend.CreateStateFile(path, content)
	if created {
		lease.files = append(lease.files, ownedFile{path: path, kind: stateFile})
	}
	if err != nil || !created {
		return rootError("protected-state-create-failed")
	}
	return nil
}

func (lease *Lease) WriteBrokerImage(ctx context.Context, image []byte) error {
	return lease.writeExecutable(ctx, lease.layout.BrokerExecutable, "broker", image)
}

func (lease *Lease) WriteControlImage(ctx context.Context, image []byte) error {
	return lease.writeExecutable(ctx, lease.layout.ControlExecutable, "control", image)
}

func (lease *Lease) writeExecutable(ctx context.Context, path string, component string, image []byte) error {
	if lease == nil || ctx == nil {
		return rootError("dependency-required")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return rootError("lease-closed")
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if lease.attempted[path] {
		return rootError(component + "-image-already-attempted")
	}
	lease.attempted[path] = true
	created, err := lease.backend.CreateExecutable(path, image)
	if created {
		lease.files = append(lease.files, ownedFile{path: path, kind: executableFile})
	}
	if err != nil || !created {
		return rootError(component + "-image-create-failed")
	}
	return nil
}

func (lease *Lease) Commit() error {
	if lease == nil {
		return rootError("lease-invalid")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return rootError("lease-closed")
	}
	lease.committed = true
	lease.closed = true
	lease.directories = nil
	lease.files = nil
	lease.attempted = nil
	return nil
}

func (lease *Lease) InstallationLayout() (installplan.Layout, error) {
	if lease == nil {
		return installplan.Layout{}, rootError("lease-invalid")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return installplan.Layout{}, rootError("lease-closed")
	}
	return lease.layout, nil
}

func (lease *Lease) Close() error {
	if lease == nil {
		return nil
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return nil
	}
	lease.closed = true
	if lease.committed {
		return nil
	}
	failed := false
	for index := len(lease.files) - 1; index >= 0; index-- {
		item := lease.files[index]
		var err error
		if item.kind == executableFile {
			err = lease.backend.RemoveExecutable(item.path)
		} else {
			err = lease.backend.RemoveStateFile(item.path)
		}
		if err != nil {
			failed = true
		}
	}
	for index := len(lease.directories) - 1; index >= 0; index-- {
		if err := lease.backend.RemoveDirectory(lease.directories[index]); err != nil {
			failed = true
		}
	}
	lease.directories = nil
	lease.files = nil
	lease.attempted = nil
	if failed {
		return rootError("rollback-failed")
	}
	return nil
}

func (lease *Lease) fixedDirectory(path string) bool {
	return path == lease.layout.Root || path == lease.layout.BinDirectory || path == lease.layout.StateDirectory
}

func (backend *windowsBackend) CreateDirectory(path string) (bool, error) {
	return backend.store.CreateNewProtectedDirectory(path)
}

func (backend *windowsBackend) VerifyDirectory(path string) error {
	return backend.store.VerifyProtectedDirectory(path)
}

func (backend *windowsBackend) CreateStateFile(path string, content []byte) (bool, error) {
	return backend.store.WriteNewProtectedFile(path, content)
}

func (backend *windowsBackend) CreateExecutable(path string, content []byte) (bool, error) {
	return backend.store.WriteNewProtectedExecutable(path, content)
}

func (backend *windowsBackend) RemoveStateFile(path string) error {
	return backend.store.RemoveProtectedStateFile(path)
}

func (backend *windowsBackend) RemoveExecutable(path string) error {
	return backend.store.RemoveProtectedExecutable(path)
}

func (backend *windowsBackend) RemoveDirectory(path string) error {
	return backend.store.RemoveProtectedDirectory(path)
}

func contextError(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return rootError("context-cancelled")
	default:
		return nil
	}
}

func rootError(rule string) error { return &Error{Rule: rule} }

var _ sharedstate.Store = (*Lease)(nil)
