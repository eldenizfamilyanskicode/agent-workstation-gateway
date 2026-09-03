package runnerpackage

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

const (
	MaxArchiveBytes      = 256 * 1024 * 1024
	MaxExpandedBytes     = 1024 * 1024 * 1024
	MaxFileBytes         = 256 * 1024 * 1024
	MaxEntries           = 8192
	MaxPathBytes         = 1024
	MaxPathDepth         = 32
	MaxRunnerVersionByte = 32
)

var versionPattern = regexp.MustCompile(`^2\.[0-9]{1,4}\.[0-9]{1,4}$`)

var requiredFiles = []string{
	"bin/Runner.Listener.exe",
	"bin/RunnerService.exe",
}

type Store interface {
	CreateDirectory(string) error
	CreateFile(string) (io.WriteCloser, error)
}

type Image struct {
	version     string
	archive     []byte
	directories []string
	files       []imageFile
}

type imageFile struct {
	path  string
	index int
	size  int64
}

type Error struct {
	Rule string
}

func (failure *Error) Error() string {
	return fmt.Sprintf("runner package denied: %s", failure.Rule)
}

func Inspect(version string, expectedSHA256 string, archive []byte) (*Image, error) {
	if len(version) == 0 || len(version) > MaxRunnerVersionByte || !versionPattern.MatchString(version) {
		return nil, packageError("version-invalid")
	}
	if !isLowerHex(expectedSHA256, 64) {
		return nil, packageError("digest-invalid")
	}
	if len(archive) == 0 || len(archive) > MaxArchiveBytes {
		return nil, packageError("archive-size-denied")
	}
	pinned := append([]byte(nil), archive...)
	sum := sha256.Sum256(pinned)
	if hex.EncodeToString(sum[:]) != expectedSHA256 {
		return nil, packageError("archive-digest-mismatch")
	}
	reader, err := zip.NewReader(bytes.NewReader(pinned), int64(len(pinned)))
	if err != nil {
		return nil, packageError("archive-invalid")
	}
	if len(reader.File) == 0 || len(reader.File) > MaxEntries {
		return nil, packageError("entry-count-denied")
	}

	directorySet := make(map[string]struct{})
	explicitDirectorySet := make(map[string]struct{})
	caseNames := make(map[string]string)
	fileSet := make(map[string]struct{})
	files := make([]imageFile, 0, len(reader.File))
	var expanded uint64
	for index, entry := range reader.File {
		name, directory, err := validateEntry(entry)
		if err != nil {
			return nil, err
		}
		if existing, exists := caseNames[strings.ToLower(name)]; exists && existing != name {
			return nil, packageError("entry-case-alias-denied")
		}
		caseNames[strings.ToLower(name)] = name
		if directory {
			if _, exists := explicitDirectorySet[name]; exists {
				return nil, packageError("entry-duplicate")
			}
			if _, exists := fileSet[name]; exists {
				return nil, packageError("entry-type-collision")
			}
			explicitDirectorySet[name] = struct{}{}
			directorySet[name] = struct{}{}
			continue
		}
		if _, exists := fileSet[name]; exists {
			return nil, packageError("entry-duplicate")
		}
		fileSet[name] = struct{}{}
		if _, directoryExists := directorySet[name]; directoryExists {
			return nil, packageError("entry-type-collision")
		}
		expanded += entry.UncompressedSize64
		if expanded > uint64(MaxExpandedBytes) {
			return nil, packageError("expanded-size-denied")
		}
		files = append(files, imageFile{path: name, index: index, size: int64(entry.UncompressedSize64)})
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if _, fileExists := fileSet[parent]; fileExists {
				return nil, packageError("entry-type-collision")
			}
			if existing, exists := caseNames[strings.ToLower(parent)]; exists && existing != parent {
				return nil, packageError("entry-case-alias-denied")
			}
			caseNames[strings.ToLower(parent)] = parent
			directorySet[parent] = struct{}{}
		}
	}
	for _, required := range requiredFiles {
		if _, exists := fileSet[required]; !exists {
			return nil, packageError("required-file-missing")
		}
	}
	directories := make([]string, 0, len(directorySet))
	for directory := range directorySet {
		directories = append(directories, directory)
	}
	sort.Slice(directories, func(left int, right int) bool {
		leftDepth := strings.Count(directories[left], "/")
		rightDepth := strings.Count(directories[right], "/")
		if leftDepth != rightDepth {
			return leftDepth < rightDepth
		}
		return directories[left] < directories[right]
	})
	sort.Slice(files, func(left int, right int) bool { return files[left].path < files[right].path })
	return &Image{version: version, archive: pinned, directories: directories, files: files}, nil
}

func (image *Image) Version() string {
	if image == nil {
		return ""
	}
	return image.version
}

func (image *Image) Extract(ctx context.Context, store Store) error {
	if image == nil || ctx == nil || store == nil || len(image.archive) == 0 {
		return packageError("extract-input-invalid")
	}
	reader, err := zip.NewReader(bytes.NewReader(image.archive), int64(len(image.archive)))
	if err != nil || len(reader.File) == 0 {
		return packageError("pinned-archive-invalid")
	}
	for _, directory := range image.directories {
		if err := contextError(ctx); err != nil {
			return err
		}
		if err := store.CreateDirectory(directory); err != nil {
			return packageError("directory-create-failed")
		}
	}
	for _, item := range image.files {
		if err := contextError(ctx); err != nil {
			return err
		}
		source, err := reader.File[item.index].Open()
		if err != nil {
			return packageError("entry-open-failed")
		}
		destination, err := store.CreateFile(item.path)
		if err != nil || destination == nil {
			_ = source.Close()
			return packageError("file-create-failed")
		}
		copyErr := copyExact(ctx, destination, source, item.size)
		destinationCloseErr := destination.Close()
		sourceCloseErr := source.Close()
		if copyErr != nil || destinationCloseErr != nil || sourceCloseErr != nil {
			return packageError("file-copy-failed")
		}
	}
	return nil
}

func validateEntry(entry *zip.File) (string, bool, error) {
	if entry == nil || entry.Flags&1 != 0 || (entry.Method != zip.Store && entry.Method != zip.Deflate) {
		return "", false, packageError("entry-format-denied")
	}
	name := entry.Name
	if len(name) == 0 || len(name) > MaxPathBytes || strings.ContainsAny(name, "\\:\x00") || strings.HasPrefix(name, "/") {
		return "", false, packageError("entry-path-invalid")
	}
	directory := strings.HasSuffix(name, "/")
	if directory {
		name = strings.TrimSuffix(name, "/")
	}
	if name == "" || path.Clean(name) != name {
		return "", false, packageError("entry-path-invalid")
	}
	segments := strings.Split(name, "/")
	if len(segments) > MaxPathDepth {
		return "", false, packageError("entry-depth-denied")
	}
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return "", false, packageError("entry-path-invalid")
		}
	}
	if platformpath.ValidateAbsolute(platformpath.Windows, `C:\runner\`+strings.Join(segments, `\`)) != nil {
		return "", false, packageError("entry-windows-path-denied")
	}
	mode := entry.Mode()
	if directory {
		if !mode.IsDir() || entry.UncompressedSize64 != 0 {
			return "", false, packageError("entry-directory-invalid")
		}
		return name, true, nil
	}
	if !mode.IsRegular() || entry.UncompressedSize64 > uint64(MaxFileBytes) {
		return "", false, packageError("entry-file-denied")
	}
	return name, false, nil
}

func copyExact(ctx context.Context, destination io.Writer, source io.Reader, size int64) error {
	buffer := make([]byte, 64*1024)
	remaining := size
	for remaining > 0 {
		if err := contextError(ctx); err != nil {
			return err
		}
		chunk := int64(len(buffer))
		if remaining < chunk {
			chunk = remaining
		}
		count, err := io.ReadFull(source, buffer[:int(chunk)])
		if err != nil || int64(count) != chunk {
			return packageError("entry-content-truncated")
		}
		if err := writeAll(destination, buffer[:count]); err != nil {
			return packageError("entry-write-failed")
		}
		remaining -= int64(count)
	}
	var extra [1]byte
	count, err := source.Read(extra[:])
	if count != 0 || err != io.EOF {
		return packageError("entry-content-invalid")
	}
	return nil
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

func contextError(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return packageError("extract-cancelled")
	default:
		return nil
	}
}

func isLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func packageError(rule string) error { return &Error{Rule: rule} }
