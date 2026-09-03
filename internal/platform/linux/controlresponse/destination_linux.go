//go:build linux

package controlresponse

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/brokerwire"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/controlclient"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

const (
	reportName    = "execution-report.json"
	stdoutName    = "stdout.bin"
	stderrName    = "stderr.bin"
	artifactsName = "artifacts"
)

type Error struct{ Rule string }

func (failure *Error) Error() string {
	return fmt.Sprintf("Linux control response destination failed: %s", failure.Rule)
}

type Destination struct {
	mu                 sync.Mutex
	finalPath          string
	stagingPath        string
	ownedFiles         []string
	ownedDirectories   []string
	artifactBegun      bool
	artifactsCommitted bool
	published          bool
	aborted            bool
}

type artifactTransaction struct {
	destination *Destination
	expected    []v1.ArtifactFile
	next        int
	open        bool
	committed   bool
	aborted     bool
}

type artifactWriter struct {
	file        *os.File
	transaction *artifactTransaction
	closed      bool
}

func New(finalPath string) (*Destination, error) {
	if platformpath.ValidateAbsolute(platformpath.Linux, finalPath) != nil || platformpath.IsFilesystemRoot(platformpath.Linux, finalPath) || filepath.Clean(finalPath) != finalPath {
		return nil, destinationError("final-path-invalid")
	}
	parent := filepath.Dir(finalPath)
	if parent == "/" || validateDirectoryChain(parent) != nil || exists(finalPath) {
		return nil, destinationError("parent-directory-denied")
	}
	staging, err := os.MkdirTemp(parent, ".awg-response-*.tmp")
	if err != nil || os.Chmod(staging, 0o700) != nil || validateExactDirectory(staging) != nil {
		if staging != "" {
			_ = os.Remove(staging)
		}
		return nil, destinationError("staging-create-failed")
	}
	return &Destination{finalPath: finalPath, stagingPath: staging, ownedDirectories: []string{staging}}, nil
}

func (destination *Destination) Begin(files []v1.ArtifactFile) (brokerwire.ArtifactTransaction, error) {
	if destination == nil || len(files) == 0 || v1.ValidateArtifactManifest(v1.ArtifactManifest{Status: v1.ArtifactStatusComplete, Files: files, Omissions: []v1.ArtifactOmission{}}) != nil {
		return nil, destinationError("artifact-list-invalid")
	}
	destination.mu.Lock()
	defer destination.mu.Unlock()
	if destination.published || destination.aborted || destination.artifactBegun {
		return nil, destinationError("artifact-transaction-state-invalid")
	}
	destination.artifactBegun = true
	return &artifactTransaction{destination: destination, expected: append([]v1.ArtifactFile(nil), files...)}, nil
}

func (transaction *artifactTransaction) Open(file v1.ArtifactFile) (io.WriteCloser, error) {
	if transaction == nil || transaction.destination == nil {
		return nil, destinationError("artifact-transaction-invalid")
	}
	destination := transaction.destination
	destination.mu.Lock()
	defer destination.mu.Unlock()
	if destination.published || destination.aborted || transaction.committed || transaction.aborted || transaction.open ||
		transaction.next >= len(transaction.expected) || transaction.expected[transaction.next] != file {
		return nil, destinationError("artifact-open-order-invalid")
	}
	current := filepath.Join(destination.stagingPath, artifactsName, file.Group)
	if err := destination.ensureDirectoryLocked(filepath.Join(destination.stagingPath, artifactsName)); err != nil {
		return nil, err
	}
	if err := destination.ensureDirectoryLocked(current); err != nil {
		return nil, err
	}
	segments := strings.Split(file.Path, "/")
	path := filepath.Join(current, filepath.FromSlash(file.Path))
	if !platformpath.Contains(platformpath.Linux, destination.stagingPath, path) {
		return nil, destinationError("artifact-path-escape")
	}
	walk := current
	for _, part := range segments[:len(segments)-1] {
		walk = filepath.Join(walk, part)
		if err := destination.ensureDirectoryLocked(walk); err != nil {
			return nil, err
		}
	}
	opened, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, destinationError("artifact-create-failed")
	}
	destination.ownedFiles = append(destination.ownedFiles, path)
	transaction.open = true
	return &artifactWriter{file: opened, transaction: transaction}, nil
}

func (writer *artifactWriter) Write(content []byte) (int, error) {
	if writer == nil || writer.file == nil || writer.closed {
		return 0, destinationError("artifact-writer-closed")
	}
	return writer.file.Write(content)
}

func (writer *artifactWriter) Close() error {
	if writer == nil || writer.transaction == nil || writer.closed {
		return nil
	}
	writer.closed = true
	syncErr := writer.file.Sync()
	closeErr := writer.file.Close()
	writer.file = nil
	destination := writer.transaction.destination
	destination.mu.Lock()
	defer destination.mu.Unlock()
	writer.transaction.open = false
	if syncErr != nil || closeErr != nil || destination.aborted {
		return destinationError("artifact-close-failed")
	}
	writer.transaction.next++
	return nil
}

func (transaction *artifactTransaction) Commit() error {
	if transaction == nil || transaction.destination == nil {
		return destinationError("artifact-transaction-invalid")
	}
	destination := transaction.destination
	destination.mu.Lock()
	defer destination.mu.Unlock()
	if destination.published || destination.aborted || transaction.committed || transaction.aborted || transaction.open || transaction.next != len(transaction.expected) {
		return destinationError("artifact-transaction-incomplete")
	}
	transaction.committed = true
	destination.artifactsCommitted = true
	return nil
}

func (transaction *artifactTransaction) Abort() error {
	if transaction == nil || transaction.destination == nil {
		return nil
	}
	transaction.aborted = true
	return transaction.destination.Abort()
}

func (destination *Destination) Publish(response brokerwire.Response) error {
	if destination == nil || v1.ValidateExecutionReport(response.Report) != nil || int64(len(response.Stdout)) != response.Report.Stdout.RetainedBytes ||
		int64(len(response.Stderr)) != response.Report.Stderr.RetainedBytes {
		return destinationError("response-invalid")
	}
	report, err := v1.MarshalCanonicalExecutionReport(response.Report)
	if err != nil {
		return destinationError("report-encode-failed")
	}
	destination.mu.Lock()
	defer destination.mu.Unlock()
	if destination.published || destination.aborted || (len(response.Report.Artifacts.Files) > 0 && !destination.artifactsCommitted) {
		return destinationError("destination-state-invalid")
	}
	for _, item := range []struct {
		name string
		body []byte
	}{{reportName, report}, {stdoutName, response.Stdout}, {stderrName, response.Stderr}} {
		if err := destination.writeNewFileLocked(filepath.Join(destination.stagingPath, item.name), item.body); err != nil {
			return err
		}
	}
	if validateDirectoryChain(filepath.Dir(destination.finalPath)) != nil || exists(destination.finalPath) {
		return destinationError("final-path-unavailable")
	}
	if err := os.Rename(destination.stagingPath, destination.finalPath); err != nil {
		return destinationError("final-publish-failed")
	}
	destination.published = true
	destination.stagingPath = ""
	destination.ownedFiles = nil
	destination.ownedDirectories = nil
	return nil
}

func (destination *Destination) Abort() error {
	if destination == nil {
		return nil
	}
	destination.mu.Lock()
	defer destination.mu.Unlock()
	if destination.published || destination.aborted {
		return nil
	}
	destination.aborted = true
	failed := false
	for index := len(destination.ownedFiles) - 1; index >= 0; index-- {
		if err := os.Remove(destination.ownedFiles[index]); err != nil && !errors.Is(err, os.ErrNotExist) {
			failed = true
		}
	}
	for index := len(destination.ownedDirectories) - 1; index >= 0; index-- {
		if err := os.Remove(destination.ownedDirectories[index]); err != nil && !errors.Is(err, os.ErrNotExist) {
			failed = true
		}
	}
	if failed {
		return destinationError("staging-cleanup-failed")
	}
	return nil
}

func (destination *Destination) ensureDirectoryLocked(path string) error {
	if !platformpath.Contains(platformpath.Linux, destination.stagingPath, path) {
		return destinationError("directory-path-escape")
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return destinationError("directory-shape-denied")
		}
		return nil
	}
	if validateExactDirectory(filepath.Dir(path)) != nil || os.Mkdir(path, 0o700) != nil || validateExactDirectory(path) != nil {
		return destinationError("directory-create-failed")
	}
	destination.ownedDirectories = append(destination.ownedDirectories, path)
	return nil
}

func (destination *Destination) writeNewFileLocked(path string, body []byte) error {
	if !platformpath.Contains(platformpath.Linux, destination.stagingPath, path) || validateExactDirectory(filepath.Dir(path)) != nil {
		return destinationError("metadata-path-denied")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return destinationError("metadata-create-failed")
	}
	destination.ownedFiles = append(destination.ownedFiles, path)
	if writeAll(file, body) != nil || file.Sync() != nil || file.Close() != nil {
		return destinationError("metadata-write-failed")
	}
	return nil
}

func validateDirectoryChain(path string) error {
	if platformpath.ValidateAbsolute(platformpath.Linux, path) != nil {
		return destinationError("directory-path-invalid")
	}
	current := "/"
	for _, part := range splitPath(path) {
		current = filepath.Join(current, part)
		if validateExactDirectory(current) != nil {
			return destinationError("directory-chain-denied")
		}
	}
	return nil
}

func validateExactDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return destinationError("directory-shape-denied")
	}
	return nil
}

func splitPath(path string) []string {
	clean := filepath.Clean(path)
	if clean == "/" || clean == "." {
		return nil
	}
	volume := filepath.VolumeName(clean)
	clean = clean[len(volume):]
	for len(clean) > 0 && os.IsPathSeparator(clean[0]) {
		clean = clean[1:]
	}
	if clean == "" {
		return nil
	}
	return strings.Split(filepath.ToSlash(clean), "/")
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil || !errors.Is(err, os.ErrNotExist)
}

func writeAll(writer io.Writer, content []byte) error {
	for len(content) > 0 {
		count, err := writer.Write(content)
		if count <= 0 || count > len(content) {
			return io.ErrShortWrite
		}
		content = content[count:]
		if err != nil {
			return err
		}
	}
	return nil
}

func destinationError(rule string) error { return &Error{Rule: rule} }

var _ controlclient.Destination = (*Destination)(nil)
var _ brokerwire.ArtifactTransaction = (*artifactTransaction)(nil)
