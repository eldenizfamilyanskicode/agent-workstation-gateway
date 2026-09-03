//go:build windows

package controlresponse

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/windows"

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

type Destination struct {
	mu                 sync.Mutex
	finalPath          string
	stagingPath        string
	ownedFiles         []string
	ownedDirectories   []string
	ownedDirectorySet  map[string]struct{}
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

type Error struct {
	Rule string
}

func (failure *Error) Error() string {
	return fmt.Sprintf("Windows control response destination failed: %s", failure.Rule)
}

func New(finalPath string) (*Destination, error) {
	if platformpath.ValidateAbsolute(platformpath.Windows, finalPath) != nil ||
		platformpath.IsFilesystemRoot(platformpath.Windows, finalPath) || filepath.Clean(finalPath) != finalPath {
		return nil, destinationError("final-path-invalid")
	}
	parent := filepath.Dir(finalPath)
	if platformpath.IsFilesystemRoot(platformpath.Windows, parent) {
		return nil, destinationError("parent-root-denied")
	}
	if err := validateDirectoryChain(parent); err != nil {
		return nil, destinationError("parent-directory-denied")
	}
	if exists(finalPath) {
		return nil, destinationError("final-path-exists")
	}

	for attempt := 0; attempt < 8; attempt++ {
		suffix, err := randomSuffix()
		if err != nil {
			return nil, destinationError("staging-name-failed")
		}
		stagingPath := filepath.Join(parent, ".awg-response-"+suffix+".tmp")
		if err := os.Mkdir(stagingPath, 0o700); err != nil {
			if errors.Is(err, os.ErrExist) {
				continue
			}
			return nil, destinationError("staging-create-failed")
		}
		destination := &Destination{
			finalPath: finalPath, stagingPath: stagingPath,
			ownedDirectories: []string{stagingPath}, ownedDirectorySet: map[string]struct{}{fold(stagingPath): {}},
		}
		if err := validateExactDirectory(stagingPath); err != nil {
			_ = destination.Abort()
			return nil, destinationError("staging-verification-failed")
		}
		return destination, nil
	}
	return nil, destinationError("staging-name-collision")
}

func (destination *Destination) Begin(files []v1.ArtifactFile) (brokerwire.ArtifactTransaction, error) {
	if destination == nil {
		return nil, destinationError("destination-invalid")
	}
	if len(files) == 0 || v1.ValidateArtifactManifest(v1.ArtifactManifest{
		Status: v1.ArtifactStatusComplete, Files: append([]v1.ArtifactFile(nil), files...), Omissions: []v1.ArtifactOmission{},
	}) != nil || validateWindowsArtifactDestinations(destination.stagingPath, files) != nil {
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
	if destination.published || destination.aborted || transaction.committed || transaction.aborted ||
		transaction.open || transaction.next >= len(transaction.expected) || transaction.expected[transaction.next] != file {
		return nil, destinationError("artifact-open-order-invalid")
	}
	if err := destination.ensureDirectoryLocked(filepath.Join(destination.stagingPath, artifactsName)); err != nil {
		return nil, err
	}
	groupPath := filepath.Join(destination.stagingPath, artifactsName, file.Group)
	if err := destination.ensureDirectoryLocked(groupPath); err != nil {
		return nil, err
	}
	current := groupPath
	segments := strings.Split(file.Path, "/")
	for _, segment := range segments[:len(segments)-1] {
		current = filepath.Join(current, segment)
		if err := destination.ensureDirectoryLocked(current); err != nil {
			return nil, err
		}
	}
	path := filepath.Join(current, segments[len(segments)-1])
	if !platformpath.Contains(platformpath.Windows, destination.stagingPath, path) {
		return nil, destinationError("artifact-path-escape")
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
	if writer == nil || writer.transaction == nil {
		return destinationError("artifact-writer-invalid")
	}
	if writer.closed {
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
	if destination.published || destination.aborted || transaction.committed || transaction.aborted ||
		transaction.open || transaction.next != len(transaction.expected) {
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
	if destination == nil {
		return destinationError("destination-invalid")
	}
	if v1.ValidateExecutionReport(response.Report) != nil ||
		int64(len(response.Stdout)) != response.Report.Stdout.RetainedBytes ||
		int64(len(response.Stderr)) != response.Report.Stderr.RetainedBytes {
		return destinationError("response-invalid")
	}
	encodedReport, err := v1.MarshalCanonicalExecutionReport(response.Report)
	if err != nil {
		return destinationError("report-encode-failed")
	}
	destination.mu.Lock()
	defer destination.mu.Unlock()
	if destination.published || destination.aborted {
		return destinationError("destination-closed")
	}
	if len(response.Report.Artifacts.Files) > 0 {
		if !destination.artifactBegun || !destination.artifactsCommitted {
			return destinationError("artifact-transaction-incomplete")
		}
	} else if destination.artifactBegun || destination.artifactsCommitted {
		return destinationError("artifact-transaction-unexpected")
	}
	for _, item := range []struct {
		name    string
		content []byte
	}{
		{name: reportName, content: encodedReport},
		{name: stdoutName, content: response.Stdout},
		{name: stderrName, content: response.Stderr},
	} {
		if err := destination.writeNewFileLocked(filepath.Join(destination.stagingPath, item.name), item.content); err != nil {
			return err
		}
	}
	if err := validateDirectoryChain(filepath.Dir(destination.finalPath)); err != nil || exists(destination.finalPath) {
		return destinationError("final-path-unavailable")
	}
	for _, path := range destination.ownedDirectories {
		if err := validateExactDirectory(path); err != nil {
			return destinationError("owned-directory-changed")
		}
	}
	if err := os.Rename(destination.stagingPath, destination.finalPath); err != nil {
		return destinationError("final-publish-failed")
	}
	destination.published = true
	destination.stagingPath = ""
	destination.ownedFiles = nil
	destination.ownedDirectories = nil
	destination.ownedDirectorySet = nil
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
	destination.ownedFiles = nil
	destination.ownedDirectories = nil
	destination.ownedDirectorySet = nil
	if failed {
		return destinationError("staging-cleanup-failed")
	}
	return nil
}

func (destination *Destination) ensureDirectoryLocked(path string) error {
	key := fold(path)
	if _, owned := destination.ownedDirectorySet[key]; owned {
		if err := validateExactDirectory(path); err != nil {
			return destinationError("owned-directory-changed")
		}
		return nil
	}
	if !platformpath.Contains(platformpath.Windows, destination.stagingPath, path) {
		return destinationError("artifact-path-escape")
	}
	if err := validateExactDirectory(filepath.Dir(path)); err != nil {
		return destinationError("artifact-parent-changed")
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return destinationError("artifact-directory-create-failed")
	}
	destination.ownedDirectories = append(destination.ownedDirectories, path)
	destination.ownedDirectorySet[key] = struct{}{}
	if err := validateExactDirectory(path); err != nil {
		return destinationError("artifact-directory-verification-failed")
	}
	return nil
}

func (destination *Destination) writeNewFileLocked(path string, content []byte) error {
	if !platformpath.Contains(platformpath.Windows, destination.stagingPath, path) {
		return destinationError("metadata-path-escape")
	}
	if err := validateExactDirectory(filepath.Dir(path)); err != nil {
		return destinationError("metadata-parent-changed")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return destinationError("metadata-create-failed")
	}
	destination.ownedFiles = append(destination.ownedFiles, path)
	if err := writeAll(file, content); err != nil {
		_ = file.Close()
		return destinationError("metadata-write-failed")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return destinationError("metadata-sync-failed")
	}
	if err := file.Close(); err != nil {
		return destinationError("metadata-close-failed")
	}
	return nil
}

func validateDirectoryChain(path string) error {
	if platformpath.ValidateAbsolute(platformpath.Windows, path) != nil {
		return destinationError("directory-path-invalid")
	}
	volume := filepath.VolumeName(path) + `\`
	current := volume
	if err := validateExactDirectory(current); err != nil {
		return err
	}
	relative := strings.TrimPrefix(path, volume)
	if relative == "" {
		return nil
	}
	for _, segment := range strings.Split(relative, `\`) {
		current = filepath.Join(current, segment)
		if err := validateExactDirectory(current); err != nil {
			return err
		}
	}
	return nil
}

func validateExactDirectory(path string) error {
	information, err := os.Lstat(path)
	if err != nil || !information.IsDir() || information.Mode()&os.ModeSymlink != 0 {
		return destinationError("directory-shape-denied")
	}
	native, ok := information.Sys().(*syscall.Win32FileAttributeData)
	if !ok || native.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return destinationError("directory-reparse-denied")
	}
	return nil
}

func validateWindowsArtifactDestinations(stagingPath string, files []v1.ArtifactFile) error {
	groups := make(map[string]string)
	directories := make(map[string]string)
	paths := make(map[string]struct{})
	for _, file := range files {
		groupKey := fold(file.Group)
		if existing, ok := groups[groupKey]; ok && existing != file.Group {
			return destinationError("artifact-case-alias-denied")
		}
		groups[groupKey] = file.Group
		current := filepath.Join(stagingPath, artifactsName, file.Group)
		if platformpath.ValidateAbsolute(platformpath.Windows, current) != nil {
			return destinationError("artifact-windows-path-invalid")
		}
		for _, segment := range strings.Split(file.Path, "/") {
			current = filepath.Join(current, segment)
			if platformpath.ValidateAbsolute(platformpath.Windows, current) != nil {
				return destinationError("artifact-windows-path-invalid")
			}
		}
		directory := filepath.Dir(current)
		for platformpath.Contains(platformpath.Windows, filepath.Join(stagingPath, artifactsName), directory) {
			key := fold(directory)
			if existing, ok := directories[key]; ok && existing != directory {
				return destinationError("artifact-case-alias-denied")
			}
			directories[key] = directory
			if platformpath.Equal(platformpath.Windows, directory, filepath.Join(stagingPath, artifactsName)) {
				break
			}
			directory = filepath.Dir(directory)
		}
		pathKey := fold(current)
		if _, exists := paths[pathKey]; exists {
			return destinationError("artifact-case-alias-denied")
		}
		paths[pathKey] = struct{}{}
	}
	return nil
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil || !errors.Is(err, os.ErrNotExist)
}

func randomSuffix() (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func writeAll(writer io.Writer, content []byte) error {
	for len(content) > 0 {
		count, err := writer.Write(content)
		if count < 0 || count > len(content) {
			return io.ErrShortWrite
		}
		content = content[count:]
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func fold(path string) string { return strings.ToLower(path) }

func destinationError(rule string) error { return &Error{Rule: rule} }

var _ controlclient.Destination = (*Destination)(nil)
var _ brokerwire.ArtifactTransaction = (*artifactTransaction)(nil)
