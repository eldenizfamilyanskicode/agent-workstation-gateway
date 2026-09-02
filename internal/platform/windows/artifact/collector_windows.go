//go:build windows

package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"unicode/utf16"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/artifactpattern"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionrun"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/process"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

const (
	maxArtifactDepth               = 32
	maxScannedEntries              = 8192
	artifactRevertFailureExitCode  = 70
	artifactHashBufferBytes        = 32 * 1024
	finalPathInitialCodeUnitBuffer = 512
)

var errScanLimit = errors.New("artifact scan entry limit")

var sensitiveSegments = map[string]struct{}{
	".aws": {}, ".azure": {}, ".git": {}, ".gnupg": {},
	".kube": {}, ".runtime": {}, ".ssh": {},
}

type Collector struct {
	configuration installconfig.Config
	tokens        process.TokenSource
}

type patternState struct {
	group     string
	pattern   string
	collected bool
	reason    v1.ArtifactOmissionReason
}

type collectionState struct {
	ctx          context.Context
	working      string
	root         string
	patterns     []patternState
	bundle       *handleBundle
	files        []v1.ArtifactFile
	fileKeys     map[string]struct{}
	scanned      int
	totalBytes   int64
	fileCount    int
	workingGuard windows.Handle
	rootGuard    windows.Handle
}

type handleBundle struct {
	mu     sync.Mutex
	files  map[string]*bundleFile
	closed bool
}

type bundleFile struct {
	file   *os.File
	opened bool
}

type bundleReader struct {
	mu     sync.Mutex
	bundle *handleBundle
	key    string
	file   *os.File
	once   sync.Once
}

var _ executionrun.ArtifactCollector = (*Collector)(nil)
var _ executionrun.ArtifactBundle = (*handleBundle)(nil)

func New(configuration installconfig.Config, tokens process.TokenSource) (*Collector, error) {
	if configuration.Platform != platformpath.Windows || installconfig.Validate(configuration) != nil {
		return nil, artifactError("installed-configuration-invalid")
	}
	if tokens == nil {
		return nil, artifactError("token-source-required")
	}
	configuration.ApprovedRoots = append([]string(nil), configuration.ApprovedRoots...)
	return &Collector{configuration: configuration, tokens: tokens}, nil
}

func (collector *Collector) Collect(ctx context.Context, plan executionrun.ArtifactPlan) (executionrun.ArtifactCollection, error) {
	if collector == nil || collector.tokens == nil {
		return executionrun.ArtifactCollection{}, artifactError("collector-invalid")
	}
	if ctx == nil {
		return executionrun.ArtifactCollection{}, artifactError("context-required")
	}
	if err := ctx.Err(); err != nil {
		return executionrun.ArtifactCollection{}, artifactCause("collection-canceled", err)
	}
	if err := collector.validatePlan(plan); err != nil {
		return executionrun.ArtifactCollection{}, err
	}
	lease, err := collector.tokens.Acquire(ctx, collector.configuration.ExecutionIdentity)
	if err != nil || lease == nil {
		return executionrun.ArtifactCollection{}, artifactError("execution-token-acquire-failed")
	}
	result, collectErr := collector.collectWithToken(ctx, plan, lease.Token())
	closeErr := lease.Close()
	if collectErr != nil || closeErr != nil {
		if result.Bundle != nil {
			_ = result.Bundle.Close()
		}
		if collectErr != nil {
			return executionrun.ArtifactCollection{}, collectErr
		}
		return executionrun.ArtifactCollection{}, artifactError("execution-token-release-failed")
	}
	return result, nil
}

func (collector *Collector) validatePlan(plan executionrun.ArtifactPlan) error {
	if !samePrincipal(plan.ExecutionIdentity, collector.configuration.ExecutionIdentity) {
		return artifactError("execution-identity-mismatch")
	}
	if err := v1.ValidateArtifactSelections(plan.Selections); err != nil || len(plan.Selections) == 0 {
		return artifactError("artifact-selections-invalid")
	}
	installedRoot := false
	for _, root := range collector.configuration.ApprovedRoots {
		installedRoot = installedRoot || platformpath.Equal(platformpath.Windows, root, plan.ApprovedRoot)
	}
	if !installedRoot {
		return artifactError("approved-root-not-installed")
	}
	if err := platformpath.ValidateAbsolute(platformpath.Windows, plan.WorkingDirectory); err != nil ||
		!platformpath.Contains(platformpath.Windows, plan.ApprovedRoot, plan.WorkingDirectory) {
		return artifactError("working-directory-not-authorized")
	}
	return nil
}

func (collector *Collector) collectWithToken(
	ctx context.Context,
	plan executionrun.ArtifactPlan,
	token windows.Token,
) (executionrun.ArtifactCollection, error) {
	if err := process.ValidateTokenIdentity(token, collector.configuration.ExecutionIdentity); err != nil {
		return executionrun.ArtifactCollection{}, artifactError("execution-token-identity-mismatch")
	}
	var impersonation windows.Token
	if err := windows.DuplicateTokenEx(
		token,
		windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE,
		nil,
		windows.SecurityImpersonation,
		windows.TokenImpersonation,
		&impersonation,
	); err != nil {
		return executionrun.ArtifactCollection{}, artifactError("execution-token-duplicate-failed")
	}
	defer impersonation.Close()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.SetThreadToken(nil, impersonation); err != nil {
		return executionrun.ArtifactCollection{}, artifactError("execution-impersonation-failed")
	}
	defer func() {
		if err := windows.RevertToSelf(); err != nil {
			os.Exit(artifactRevertFailureExitCode)
		}
	}()
	return collectImpersonated(ctx, plan)
}

func collectImpersonated(ctx context.Context, plan executionrun.ArtifactPlan) (executionrun.ArtifactCollection, error) {
	rootGuard, rootFinal, err := openVerifiedDirectory(plan.ApprovedRoot)
	if err != nil || !platformpath.Equal(platformpath.Windows, rootFinal, plan.ApprovedRoot) {
		if rootGuard != 0 {
			_ = windows.CloseHandle(rootGuard)
		}
		return executionrun.ArtifactCollection{}, artifactError("approved-root-verification-failed")
	}
	workingGuard, workingFinal, err := openVerifiedDirectory(plan.WorkingDirectory)
	if err != nil || !platformpath.Equal(platformpath.Windows, workingFinal, plan.WorkingDirectory) ||
		!platformpath.Contains(platformpath.Windows, rootFinal, workingFinal) {
		_ = windows.CloseHandle(rootGuard)
		if workingGuard != 0 {
			_ = windows.CloseHandle(workingGuard)
		}
		return executionrun.ArtifactCollection{}, artifactError("working-directory-verification-failed")
	}
	state := &collectionState{
		ctx: ctx, working: workingFinal, root: rootFinal,
		bundle:       &handleBundle{files: make(map[string]*bundleFile)},
		files:        make([]v1.ArtifactFile, 0),
		fileKeys:     make(map[string]struct{}),
		workingGuard: workingGuard, rootGuard: rootGuard,
	}
	defer windows.CloseHandle(state.workingGuard)
	defer windows.CloseHandle(state.rootGuard)
	for _, selection := range plan.Selections {
		for _, pattern := range selection.Paths {
			state.patterns = append(state.patterns, patternState{group: selection.Name, pattern: pattern})
		}
	}
	if err := state.walk(); err != nil {
		_ = state.bundle.Close()
		return executionrun.ArtifactCollection{}, err
	}
	manifest := state.manifest()
	if err := v1.ValidateArtifactManifest(manifest); err != nil {
		_ = state.bundle.Close()
		return executionrun.ArtifactCollection{}, artifactError("artifact-manifest-invalid")
	}
	if len(manifest.Files) == 0 {
		_ = state.bundle.Close()
		return executionrun.ArtifactCollection{Manifest: manifest}, nil
	}
	return executionrun.ArtifactCollection{Manifest: manifest, Bundle: state.bundle}, nil
}

func (state *collectionState) walk() error {
	err := filepath.WalkDir(state.working, func(candidate string, entry fs.DirEntry, entryErr error) error {
		if err := state.ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(state.working, candidate)
		if err != nil || strings.HasPrefix(relative, "..") {
			return artifactError("enumeration-path-invalid")
		}
		if relative == "." {
			if entryErr != nil {
				return artifactError("working-directory-read-failed")
			}
			return nil
		}
		relative = filepath.ToSlash(relative)
		state.scanned++
		if state.scanned > maxScannedEntries {
			state.noteAll(v1.ArtifactOmissionFileLimit)
			return errScanLimit
		}
		if entryErr != nil {
			state.notePrefix(relative, v1.ArtifactOmissionReadFailed)
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if err := v1.ValidateArtifactFilePath(relative); err != nil {
			state.notePrefix(relative, v1.ArtifactOmissionPolicyRejected)
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		depth := strings.Count(relative, "/") + 1
		if depth > maxArtifactDepth {
			state.notePrefix(relative, v1.ArtifactOmissionPolicyRejected)
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if hasSensitiveSegment(relative) {
			state.notePrefix(relative, v1.ArtifactOmissionPolicyRejected)
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		attributes, err := fileAttributes(candidate)
		if err != nil {
			state.notePrefix(relative, v1.ArtifactOmissionReadFailed)
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		isDirectory := attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
		if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			state.notePrefix(relative, v1.ArtifactOmissionLinkRejected)
			if isDirectory {
				return filepath.SkipDir
			}
			return nil
		}
		if isDirectory {
			return nil
		}
		return state.collectCandidate(candidate, relative)
	})
	if errors.Is(err, errScanLimit) {
		return nil
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return artifactCause("collection-canceled", err)
		}
		return artifactCause("enumeration-failed", err)
	}
	return nil
}

func (state *collectionState) collectCandidate(candidate string, relative string) error {
	groupPatterns := make(map[string][]int)
	groupOrder := make([]string, 0)
	for index := range state.patterns {
		matched, err := artifactpattern.Match(state.patterns[index].pattern, relative)
		if err != nil {
			return artifactError("artifact-pattern-invalid")
		}
		if !matched {
			continue
		}
		if _, exists := groupPatterns[state.patterns[index].group]; !exists {
			groupOrder = append(groupOrder, state.patterns[index].group)
		}
		groupPatterns[state.patterns[index].group] = append(groupPatterns[state.patterns[index].group], index)
	}
	for _, group := range groupOrder {
		indices := groupPatterns[group]
		if _, duplicate := state.fileKeys[bundleKey(group, relative)]; duplicate {
			for _, index := range indices {
				state.patterns[index].collected = true
			}
			continue
		}
		if state.fileCount >= v1.MaxArtifactFiles {
			state.note(indices, v1.ArtifactOmissionFileLimit)
			continue
		}
		remainingBytes := int64(v1.MaxTotalArtifactBytes) - state.totalBytes
		file, size, digest, reason := openStableFile(state.ctx, candidate, state.working, state.root, remainingBytes)
		if reason != "" {
			state.note(indices, reason)
			continue
		}
		metadata := v1.ArtifactFile{Group: group, Path: relative, SHA256: digest, SizeBytes: size}
		key := bundleKey(group, relative)
		state.bundle.files[key] = &bundleFile{file: file}
		state.fileKeys[key] = struct{}{}
		state.files = append(state.files, metadata)
		state.fileCount++
		state.totalBytes += size
		for _, index := range indices {
			state.patterns[index].collected = true
		}
	}
	return nil
}

func (state *collectionState) notePrefix(prefix string, reason v1.ArtifactOmissionReason) {
	for index := range state.patterns {
		matched, err := artifactpattern.Match(state.patterns[index].pattern, prefix)
		if err == nil && !matched {
			matched, err = artifactpattern.CouldMatchDescendant(state.patterns[index].pattern, prefix)
		}
		if err == nil && matched && state.patterns[index].reason == "" {
			state.patterns[index].reason = reason
		}
	}
}

func (state *collectionState) note(indices []int, reason v1.ArtifactOmissionReason) {
	for _, index := range indices {
		if state.patterns[index].reason == "" {
			state.patterns[index].reason = reason
		}
	}
}

func (state *collectionState) noteAll(reason v1.ArtifactOmissionReason) {
	for index := range state.patterns {
		if state.patterns[index].reason == "" {
			state.patterns[index].reason = reason
		}
	}
}

func (state *collectionState) manifest() v1.ArtifactManifest {
	sort.Slice(state.files, func(left int, right int) bool {
		if state.files[left].Group != state.files[right].Group {
			return state.files[left].Group < state.files[right].Group
		}
		return state.files[left].Path < state.files[right].Path
	})
	omissions := make([]v1.ArtifactOmission, 0)
	for _, pattern := range state.patterns {
		reason := pattern.reason
		if reason == "" && !pattern.collected {
			reason = v1.ArtifactOmissionNoMatch
		}
		if reason != "" {
			omissions = append(omissions, v1.ArtifactOmission{
				Group: pattern.group, Pattern: pattern.pattern, Reason: reason,
			})
		}
	}
	status := v1.ArtifactStatusComplete
	if len(state.files) == 0 {
		status = v1.ArtifactStatusFailed
	} else if len(omissions) > 0 {
		status = v1.ArtifactStatusCompleteWithOmissions
	}
	return v1.ArtifactManifest{Status: status, Files: state.files, Omissions: omissions}
}

func openStableFile(
	ctx context.Context,
	path string,
	working string,
	root string,
	remainingBytes int64,
) (*os.File, int64, string, v1.ArtifactOmissionReason) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, 0, "", v1.ArtifactOmissionPolicyRejected
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_SEQUENTIAL_SCAN,
		0,
	)
	if err != nil {
		return nil, 0, "", v1.ArtifactOmissionReadFailed
	}
	file := os.NewFile(uintptr(handle), "artifact")
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, 0, "", v1.ArtifactOmissionReadFailed
	}
	fail := func(reason v1.ArtifactOmissionReason) (*os.File, int64, string, v1.ArtifactOmissionReason) {
		_ = file.Close()
		return nil, 0, "", reason
	}
	var information windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(handle, &information) != nil {
		return fail(v1.ArtifactOmissionReadFailed)
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || information.NumberOfLinks != 1 {
		return fail(v1.ArtifactOmissionLinkRejected)
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return fail(v1.ArtifactOmissionUnsupportedType)
	}
	fileType, err := windows.GetFileType(handle)
	if err != nil || fileType != windows.FILE_TYPE_DISK {
		return fail(v1.ArtifactOmissionUnsupportedType)
	}
	final, err := finalCanonicalPath(handle)
	if err != nil || !platformpath.Equal(platformpath.Windows, final, path) ||
		!platformpath.Contains(platformpath.Windows, working, final) ||
		!platformpath.Contains(platformpath.Windows, root, final) {
		return fail(v1.ArtifactOmissionLinkRejected)
	}
	size := int64(information.FileSizeHigh)<<32 | int64(information.FileSizeLow)
	if size < 0 || size > v1.MaxArtifactFileBytes || size > remainingBytes {
		return fail(v1.ArtifactOmissionByteLimit)
	}
	hash := sha256.New()
	read, err := io.CopyBuffer(hash, &contextReader{ctx: ctx, reader: file}, make([]byte, artifactHashBufferBytes))
	if err != nil {
		if ctx.Err() != nil {
			return fail(v1.ArtifactOmissionCollectionFailed)
		}
		return fail(v1.ArtifactOmissionReadFailed)
	}
	if read != size {
		return fail(v1.ArtifactOmissionReadFailed)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fail(v1.ArtifactOmissionReadFailed)
	}
	return file, size, hex.EncodeToString(hash.Sum(nil)), ""
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

func openVerifiedDirectory(path string) (windows.Handle, string, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, "", err
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return 0, "", err
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil ||
		information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
		information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(handle)
		return 0, "", artifactError("directory-handle-invalid")
	}
	final, err := finalCanonicalPath(handle)
	if err != nil {
		_ = windows.CloseHandle(handle)
		return 0, "", err
	}
	return handle, final, nil
}

func finalCanonicalPath(handle windows.Handle) (string, error) {
	buffer := make([]uint16, finalPathInitialCodeUnitBuffer)
	for {
		length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
		if err != nil {
			return "", err
		}
		if length < uint32(len(buffer)) {
			value := string(utf16.Decode(buffer[:length]))
			if strings.HasPrefix(value, `\\?\UNC\`) {
				return "", artifactError("unc-path-denied")
			}
			value = strings.TrimPrefix(value, `\\?\`)
			if len(value) >= 2 && value[1] == ':' && value[0] >= 'a' && value[0] <= 'z' {
				value = strings.ToUpper(value[:1]) + value[1:]
			}
			if err := platformpath.ValidateAbsolute(platformpath.Windows, value); err != nil {
				return "", artifactError("final-path-invalid")
			}
			return value, nil
		}
		buffer = make([]uint16, int(length)+1)
	}
}

func fileAttributes(path string) (uint32, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	attributes, err := windows.GetFileAttributes(pointer)
	if err != nil || attributes == windows.INVALID_FILE_ATTRIBUTES {
		return 0, err
	}
	return attributes, nil
}

func hasSensitiveSegment(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		lower := strings.ToLower(segment)
		if _, denied := sensitiveSegments[lower]; denied || lower == ".env" || strings.HasPrefix(lower, ".env.") {
			return true
		}
	}
	return false
}

func samePrincipal(left installconfig.Principal, right installconfig.Principal) bool {
	return left.Name == right.Name && strings.EqualFold(left.Identifier, right.Identifier) &&
		strings.EqualFold(left.PrimaryGroupIdentifier, right.PrimaryGroupIdentifier)
}

func bundleKey(group string, path string) string { return group + "\x00" + path }

func (bundle *handleBundle) Open(group string, path string) (io.ReadCloser, error) {
	if bundle == nil {
		return nil, artifactError("bundle-invalid")
	}
	bundle.mu.Lock()
	defer bundle.mu.Unlock()
	if bundle.closed {
		return nil, artifactError("bundle-closed")
	}
	key := bundleKey(group, path)
	entry := bundle.files[key]
	if entry == nil || entry.file == nil || entry.opened {
		return nil, artifactError("artifact-not-available")
	}
	if _, err := entry.file.Seek(0, io.SeekStart); err != nil {
		return nil, artifactError("artifact-seek-failed")
	}
	entry.opened = true
	return &bundleReader{bundle: bundle, key: key, file: entry.file}, nil
}

func (bundle *handleBundle) Close() error {
	if bundle == nil {
		return nil
	}
	bundle.mu.Lock()
	defer bundle.mu.Unlock()
	if bundle.closed {
		return nil
	}
	bundle.closed = true
	failed := false
	for key, entry := range bundle.files {
		if entry.file != nil && entry.file.Close() != nil {
			failed = true
		}
		delete(bundle.files, key)
	}
	if failed {
		return artifactError("bundle-close-failed")
	}
	return nil
}

func (reader *bundleReader) Read(buffer []byte) (int, error) {
	if reader == nil {
		return 0, artifactError("artifact-reader-invalid")
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.file == nil {
		return 0, artifactError("artifact-reader-invalid")
	}
	return reader.file.Read(buffer)
}

func (reader *bundleReader) Close() error {
	if reader == nil {
		return nil
	}
	var closeErr error
	reader.once.Do(func() {
		reader.mu.Lock()
		defer reader.mu.Unlock()
		reader.bundle.mu.Lock()
		defer reader.bundle.mu.Unlock()
		entry := reader.bundle.files[reader.key]
		if entry != nil && entry.file == reader.file {
			closeErr = entry.file.Close()
			delete(reader.bundle.files, reader.key)
		}
		reader.file = nil
	})
	if closeErr != nil {
		return artifactError("artifact-reader-close-failed")
	}
	return nil
}
