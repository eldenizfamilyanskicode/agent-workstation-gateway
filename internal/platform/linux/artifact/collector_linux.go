//go:build linux

package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/artifactpattern"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionrun"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	linuxprocess "github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/linux/process"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/strictjson"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

const (
	HelperOperation   = "__linux-artifacts"
	maxArtifactDepth  = 32
	maxScannedEntries = 8192
	maxPlanBytes      = 256 * 1024
)

var sensitiveSegments = map[string]struct{}{
	".aws": {}, ".azure": {}, ".git": {}, ".gnupg": {}, ".kube": {}, ".runtime": {}, ".ssh": {},
}

type Error struct{ Rule string }

func (failure *Error) Error() string {
	return fmt.Sprintf("Linux artifact collection failed: %s", failure.Rule)
}

type Collector struct{ configuration installconfig.Config }

type helperInput struct {
	WorkingDirectory string                 `json:"working_directory"`
	ApprovedRoot     string                 `json:"approved_root"`
	Selections       []v1.ArtifactSelection `json:"selections"`
}

type helperFile struct {
	Group string `json:"group"`
	Path  string `json:"path"`
	Size  int64  `json:"size"`
}

type helperPlan struct {
	Files     []helperFile          `json:"files"`
	Omissions []v1.ArtifactOmission `json:"omissions"`
}

type helperOpenedFile struct {
	metadata helperFile
	file     *os.File
}

type patternState struct {
	group     string
	pattern   string
	collected bool
	reason    v1.ArtifactOmissionReason
}

type fileBundle struct {
	mu     sync.Mutex
	root   string
	files  map[string]string
	opened map[string]bool
	closed bool
}

func New(configuration installconfig.Config) (*Collector, error) {
	if os.Geteuid() != 0 || configuration.Platform != platformpath.Linux || installconfig.Validate(configuration) != nil {
		return nil, artifactError("installed-configuration-invalid")
	}
	configuration.ApprovedRoots = append([]string(nil), configuration.ApprovedRoots...)
	return &Collector{configuration: configuration}, nil
}

func (collector *Collector) Collect(ctx context.Context, plan executionrun.ArtifactPlan) (executionrun.ArtifactCollection, error) {
	if collector == nil || ctx == nil || plan.ExecutionIdentity != collector.configuration.ExecutionIdentity ||
		v1.ValidateArtifactSelections(plan.Selections) != nil || len(plan.Selections) == 0 {
		return executionrun.ArtifactCollection{}, artifactError("collection-input-invalid")
	}
	installedRoot := false
	for _, root := range collector.configuration.ApprovedRoots {
		installedRoot = installedRoot || root == plan.ApprovedRoot
	}
	if !installedRoot || platformpath.ValidateAbsolute(platformpath.Linux, plan.WorkingDirectory) != nil ||
		!platformpath.Contains(platformpath.Linux, plan.ApprovedRoot, plan.WorkingDirectory) {
		return executionrun.ArtifactCollection{}, artifactError("working-directory-not-authorized")
	}
	uid, gid, err := linuxprocess.PrincipalIDs(plan.ExecutionIdentity)
	if err != nil {
		return executionrun.ArtifactCollection{}, artifactError("execution-identity-invalid")
	}
	input, err := json.Marshal(helperInput{WorkingDirectory: plan.WorkingDirectory, ApprovedRoot: plan.ApprovedRoot, Selections: plan.Selections})
	if err != nil || len(input) > maxPlanBytes {
		return executionrun.ArtifactCollection{}, artifactError("helper-input-invalid")
	}
	command := exec.CommandContext(ctx, "/proc/self/exe", HelperOperation, strconv.FormatUint(uint64(uid), 10), strconv.FormatUint(uint64(gid), 10))
	command.Dir = plan.WorkingDirectory
	command.Env = []string{}
	command.Stdin = bytes.NewReader(input)
	command.Stderr = io.Discard
	command.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}, Setpgid: true, Pdeathsig: syscall.SIGKILL,
	}
	stdout, err := command.StdoutPipe()
	if err != nil || command.Start() != nil {
		return executionrun.ArtifactCollection{}, artifactError("helper-start-failed")
	}
	collection, readErr := receiveCollection(ctx, stdout, plan.Selections)
	waitErr := command.Wait()
	if readErr != nil || waitErr != nil {
		if collection.Bundle != nil {
			_ = collection.Bundle.Close()
		}
		return executionrun.ArtifactCollection{}, artifactError("helper-failed")
	}
	return collection, nil
}

func receiveCollection(ctx context.Context, reader io.Reader, selections []v1.ArtifactSelection) (executionrun.ArtifactCollection, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return executionrun.ArtifactCollection{}, artifactError("plan-header-read-failed")
	}
	length := int(binary.BigEndian.Uint32(header[:]))
	if length <= 0 || length > maxPlanBytes {
		return executionrun.ArtifactCollection{}, artifactError("plan-size-invalid")
	}
	encoded := make([]byte, length)
	if _, err := io.ReadFull(reader, encoded); err != nil {
		return executionrun.ArtifactCollection{}, artifactError("plan-read-failed")
	}
	var plan helperPlan
	if err := strictjson.DecodeObject(encoded, maxPlanBytes, &plan); err != nil || validateHelperPlan(plan, selections) != nil {
		return executionrun.ArtifactCollection{}, artifactError("plan-invalid")
	}
	root, err := os.MkdirTemp("/run/agent-workstation-gateway", "artifacts-")
	if err != nil || os.Chmod(root, 0o700) != nil {
		return executionrun.ArtifactCollection{}, artifactError("bundle-create-failed")
	}
	bundle := &fileBundle{root: root, files: make(map[string]string), opened: make(map[string]bool)}
	files := make([]v1.ArtifactFile, 0, len(plan.Files))
	for index, item := range plan.Files {
		if err := ctx.Err(); err != nil {
			_ = bundle.Close()
			return executionrun.ArtifactCollection{}, artifactError("collection-cancelled")
		}
		path := filepath.Join(root, strconv.Itoa(index))
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			_ = bundle.Close()
			return executionrun.ArtifactCollection{}, artifactError("bundle-file-create-failed")
		}
		hasher := sha256.New()
		_, copyErr := io.CopyN(io.MultiWriter(file, hasher), reader, item.Size)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			_ = bundle.Close()
			return executionrun.ArtifactCollection{}, artifactError("artifact-content-read-failed")
		}
		metadata := v1.ArtifactFile{Group: item.Group, Path: item.Path, SizeBytes: item.Size, SHA256: hex.EncodeToString(hasher.Sum(nil))}
		files = append(files, metadata)
		bundle.files[bundleKey(item.Group, item.Path)] = path
	}
	var extra [1]byte
	if count, err := reader.Read(extra[:]); count != 0 || err != io.EOF {
		_ = bundle.Close()
		return executionrun.ArtifactCollection{}, artifactError("helper-trailing-data")
	}
	status := v1.ArtifactStatusComplete
	if len(files) == 0 {
		status = v1.ArtifactStatusFailed
	} else if len(plan.Omissions) > 0 {
		status = v1.ArtifactStatusCompleteWithOmissions
	}
	manifest := v1.ArtifactManifest{Status: status, Files: files, Omissions: plan.Omissions}
	if v1.ValidateArtifactManifest(manifest) != nil {
		_ = bundle.Close()
		return executionrun.ArtifactCollection{}, artifactError("manifest-invalid")
	}
	if len(files) == 0 {
		_ = bundle.Close()
		return executionrun.ArtifactCollection{Manifest: manifest}, nil
	}
	return executionrun.ArtifactCollection{Manifest: manifest, Bundle: bundle}, nil
}

func validateHelperPlan(plan helperPlan, selections []v1.ArtifactSelection) error {
	if plan.Files == nil || plan.Omissions == nil || len(plan.Files) > v1.MaxArtifactFiles || len(plan.Omissions) > v1.MaxArtifactOmissions {
		return artifactError("plan-shape-invalid")
	}
	groups := make(map[string][]string)
	for _, selection := range selections {
		groups[selection.Name] = selection.Paths
	}
	seen := make(map[string]struct{})
	var total int64
	for _, file := range plan.Files {
		if v1.ValidateArtifactFilePath(file.Path) != nil || file.Size < 0 || file.Size > v1.MaxArtifactFileBytes {
			return artifactError("file-invalid")
		}
		patterns, ok := groups[file.Group]
		matched := false
		for _, pattern := range patterns {
			value, err := artifactpattern.Match(pattern, file.Path)
			if err != nil {
				return err
			}
			matched = matched || value
		}
		key := bundleKey(file.Group, file.Path)
		if !ok || !matched {
			return artifactError("file-not-selected")
		}
		if _, duplicate := seen[key]; duplicate {
			return artifactError("file-duplicate")
		}
		seen[key] = struct{}{}
		total += file.Size
		if total > v1.MaxTotalArtifactBytes {
			return artifactError("total-size-denied")
		}
	}
	for _, omission := range plan.Omissions {
		patterns, ok := groups[omission.Group]
		found := false
		for _, pattern := range patterns {
			found = found || pattern == omission.Pattern
		}
		if !ok || !found || omission.Reason == "" {
			return artifactError("omission-invalid")
		}
	}
	return nil
}

func RunHelper(args []string) int {
	if len(args) != 3 || args[0] != HelperOperation || !linuxprocess.PrepareHelperIdentity(args[1], args[2]) {
		return 70
	}
	encoded, err := io.ReadAll(io.LimitReader(os.Stdin, maxPlanBytes+1))
	if err != nil || len(encoded) == 0 || len(encoded) > maxPlanBytes {
		return 64
	}
	var input helperInput
	if strictjson.DecodeObject(encoded, maxPlanBytes, &input) != nil || v1.ValidateArtifactSelections(input.Selections) != nil || len(input.Selections) == 0 {
		return 64
	}
	working, err := filepath.EvalSymlinks(input.WorkingDirectory)
	root, rootErr := filepath.EvalSymlinks(input.ApprovedRoot)
	current, currentErr := os.Getwd()
	if err != nil || rootErr != nil || currentErr != nil || working != current || root != input.ApprovedRoot ||
		!platformpath.Contains(platformpath.Linux, root, working) {
		return 70
	}
	opened, omissions, err := collectFiles(working, input.Selections)
	if err != nil {
		return 1
	}
	defer func() {
		for _, item := range opened {
			_ = item.file.Close()
		}
	}()
	files := make([]helperFile, len(opened))
	for index := range opened {
		files[index] = opened[index].metadata
	}
	plan, err := json.Marshal(helperPlan{Files: files, Omissions: omissions})
	if err != nil || len(plan) > maxPlanBytes {
		return 1
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(plan)))
	if writeAll(os.Stdout, header[:]) != nil || writeAll(os.Stdout, plan) != nil {
		return 1
	}
	for _, item := range opened {
		if _, err := item.file.Seek(0, io.SeekStart); err != nil {
			return 1
		}
		if copied, err := io.CopyN(os.Stdout, item.file, item.metadata.Size); err != nil || copied != item.metadata.Size {
			return 1
		}
		var extra [1]byte
		if count, err := item.file.Read(extra[:]); count != 0 || err != io.EOF {
			return 1
		}
	}
	return 0
}

func collectFiles(working string, selections []v1.ArtifactSelection) ([]helperOpenedFile, []v1.ArtifactOmission, error) {
	patterns := make([]patternState, 0)
	for _, selection := range selections {
		for _, pattern := range selection.Paths {
			patterns = append(patterns, patternState{group: selection.Name, pattern: pattern})
		}
	}
	opened := make([]helperOpenedFile, 0)
	keys := make(map[string]struct{})
	var total int64
	scanned := 0
	err := filepath.WalkDir(working, func(candidate string, entry fs.DirEntry, entryErr error) error {
		if entryErr != nil {
			return nil
		}
		relative, err := filepath.Rel(working, candidate)
		if err != nil || strings.HasPrefix(relative, "..") {
			return artifactError("enumeration-path-invalid")
		}
		if relative == "." {
			return nil
		}
		relative = filepath.ToSlash(relative)
		scanned++
		if scanned > maxScannedEntries {
			noteAll(patterns, v1.ArtifactOmissionFileLimit)
			return fs.SkipAll
		}
		if v1.ValidateArtifactFilePath(relative) != nil || strings.Count(relative, "/")+1 > maxArtifactDepth || hasSensitiveSegment(relative) {
			notePrefix(patterns, relative, v1.ArtifactOmissionPolicyRejected)
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			notePrefix(patterns, relative, v1.ArtifactOmissionLinkRejected)
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		matched := make(map[string][]int)
		for index := range patterns {
			ok, matchErr := artifactpattern.Match(patterns[index].pattern, relative)
			if matchErr != nil {
				return matchErr
			}
			if ok {
				matched[patterns[index].group] = append(matched[patterns[index].group], index)
			}
		}
		groups := make([]string, 0, len(matched))
		for group := range matched {
			groups = append(groups, group)
		}
		sort.Strings(groups)
		for _, group := range groups {
			indices := matched[group]
			key := bundleKey(group, relative)
			if _, duplicate := keys[key]; duplicate {
				continue
			}
			if len(opened) >= v1.MaxArtifactFiles {
				note(patterns, indices, v1.ArtifactOmissionFileLimit)
				continue
			}
			file, size, reason := openStableFile(candidate, working, v1.MaxTotalArtifactBytes-total)
			if reason != "" {
				note(patterns, indices, reason)
				continue
			}
			opened = append(opened, helperOpenedFile{metadata: helperFile{Group: group, Path: relative, Size: size}, file: file})
			keys[key] = struct{}{}
			total += size
			for _, index := range indices {
				patterns[index].collected = true
			}
		}
		return nil
	})
	if err != nil {
		for _, item := range opened {
			_ = item.file.Close()
		}
		return nil, nil, err
	}
	sort.Slice(opened, func(left, right int) bool {
		if opened[left].metadata.Group != opened[right].metadata.Group {
			return opened[left].metadata.Group < opened[right].metadata.Group
		}
		return opened[left].metadata.Path < opened[right].metadata.Path
	})
	omissions := make([]v1.ArtifactOmission, 0)
	for _, pattern := range patterns {
		reason := pattern.reason
		if reason == "" && !pattern.collected {
			reason = v1.ArtifactOmissionNoMatch
		}
		if reason != "" {
			omissions = append(omissions, v1.ArtifactOmission{Group: pattern.group, Pattern: pattern.pattern, Reason: reason})
		}
	}
	return opened, omissions, nil
}

func openStableFile(candidate, working string, remaining int64) (*os.File, int64, v1.ArtifactOmissionReason) {
	fd, err := unix.Open(candidate, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, 0, v1.ArtifactOmissionReadFailed
	}
	file := os.NewFile(uintptr(fd), "artifact")
	fail := func(reason v1.ArtifactOmissionReason) (*os.File, int64, v1.ArtifactOmissionReason) {
		_ = file.Close()
		return nil, 0, reason
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil {
		return fail(v1.ArtifactOmissionReadFailed)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fail(v1.ArtifactOmissionUnsupportedType)
	}
	if stat.Nlink != 1 {
		return fail(v1.ArtifactOmissionLinkRejected)
	}
	final, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil || final != candidate || !platformpath.Contains(platformpath.Linux, working, final) {
		return fail(v1.ArtifactOmissionLinkRejected)
	}
	if stat.Size < 0 || stat.Size > v1.MaxArtifactFileBytes || stat.Size > remaining {
		return fail(v1.ArtifactOmissionByteLimit)
	}
	return file, stat.Size, ""
}

func notePrefix(patterns []patternState, prefix string, reason v1.ArtifactOmissionReason) {
	for index := range patterns {
		matched, err := artifactpattern.Match(patterns[index].pattern, prefix)
		if err == nil && !matched {
			matched, err = artifactpattern.CouldMatchDescendant(patterns[index].pattern, prefix)
		}
		if err == nil && matched && patterns[index].reason == "" {
			patterns[index].reason = reason
		}
	}
}

func note(patterns []patternState, indices []int, reason v1.ArtifactOmissionReason) {
	for _, index := range indices {
		if patterns[index].reason == "" {
			patterns[index].reason = reason
		}
	}
}

func noteAll(patterns []patternState, reason v1.ArtifactOmissionReason) {
	for index := range patterns {
		if patterns[index].reason == "" {
			patterns[index].reason = reason
		}
	}
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

func (bundle *fileBundle) Open(group, path string) (io.ReadCloser, error) {
	if bundle == nil {
		return nil, artifactError("bundle-invalid")
	}
	bundle.mu.Lock()
	defer bundle.mu.Unlock()
	key := bundleKey(group, path)
	filePath := bundle.files[key]
	if bundle.closed || filePath == "" || bundle.opened[key] {
		return nil, artifactError("artifact-not-available")
	}
	file, err := os.OpenFile(filePath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, artifactError("artifact-open-failed")
	}
	bundle.opened[key] = true
	return file, nil
}

func (bundle *fileBundle) Close() error {
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
	for _, path := range bundle.files {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			failed = true
		}
	}
	if err := os.Remove(bundle.root); err != nil && !errors.Is(err, os.ErrNotExist) {
		failed = true
	}
	if failed {
		return artifactError("bundle-cleanup-failed")
	}
	return nil
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

func bundleKey(group, path string) string { return group + "\x00" + path }
func artifactError(rule string) error     { return &Error{Rule: rule} }

var _ executionrun.ArtifactCollector = (*Collector)(nil)
var _ executionrun.ArtifactBundle = (*fileBundle)(nil)
