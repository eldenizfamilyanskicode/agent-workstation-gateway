package runnerpackage

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"
)

type archiveEntry struct {
	name    string
	content []byte
	mode    os.FileMode
}

type memoryStore struct {
	directories []string
	files       map[string]*memoryWriter
	symlinks    map[string]string
	failPath    string
}

func (store *memoryStore) CreateDirectory(path string) error {
	if path == store.failPath {
		return errors.New("synthetic directory failure")
	}
	store.directories = append(store.directories, path)
	return nil
}

func (store *memoryStore) CreateFile(path string) (io.WriteCloser, error) {
	return store.CreateFileMode(path, 0o600)
}

func (store *memoryStore) CreateFileMode(path string, _ fs.FileMode) (io.WriteCloser, error) {
	if path == store.failPath {
		return nil, errors.New("synthetic file failure")
	}
	if store.files == nil {
		store.files = make(map[string]*memoryWriter)
	}
	writer := &memoryWriter{}
	store.files[path] = writer
	return writer, nil
}

func (store *memoryStore) CreateSymlink(path, target string) error {
	if path == store.failPath {
		return errors.New("synthetic link failure")
	}
	if store.symlinks == nil {
		store.symlinks = make(map[string]string)
	}
	store.symlinks[path] = target
	return nil
}

type memoryWriter struct {
	bytes.Buffer
	closed bool
}

type discardStore struct {
	files int
}

type discardWriter struct{ io.Writer }

func (*discardStore) CreateDirectory(string) error { return nil }
func (store *discardStore) CreateFile(string) (io.WriteCloser, error) {
	return store.CreateFileMode("", 0o600)
}
func (store *discardStore) CreateFileMode(string, fs.FileMode) (io.WriteCloser, error) {
	store.files++
	return discardWriter{Writer: io.Discard}, nil
}
func (*discardStore) CreateSymlink(string, string) error { return nil }
func (discardWriter) Close() error                       { return nil }

func (writer *memoryWriter) Close() error {
	writer.closed = true
	return nil
}

func TestInspectAndExtractPinnedRunnerPackage(t *testing.T) {
	archive := buildArchive(t, []archiveEntry{
		{name: "bin/Runner.Listener.exe", content: []byte("listener")},
		{name: "bin/RunnerService.exe", content: []byte("service")},
		{name: "externals/tool.txt", content: []byte("tool")},
		{name: "run.cmd", content: []byte("run")},
	})
	image, err := Inspect("2.337.0", digest(archive), archive)
	if err != nil {
		t.Fatal(err)
	}
	archive[0] ^= 0xff
	store := &memoryStore{}
	if err := image.Extract(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string]string{
		"bin/Runner.Listener.exe": "listener", "bin/RunnerService.exe": "service",
		"externals/tool.txt": "tool", "run.cmd": "run",
	} {
		writer := store.files[path]
		if writer == nil || !writer.closed || writer.String() != content {
			t.Fatalf("extracted file changed for %s: %#v", path, writer)
		}
	}
	if strings.Join(store.directories, ",") != "bin,externals" {
		t.Fatalf("directory order is not deterministic: %#v", store.directories)
	}
}

func TestProductionInspectionRejectsCallerPairedArchiveAndDigest(t *testing.T) {
	archive := validArchive(t)
	if image, err := Inspect(PinnedWindowsX64Version, digest(archive), archive); err != nil || image.PinnedWindowsX64() {
		t.Fatal("generic validation incorrectly established the production trust pin")
	}
	_, err := InspectPinnedWindowsX64(archive)
	assertPackageError(t, err, "pinned-archive-size-mismatch")
}

func TestPinnedWindowsX64ArchiveWhenSupplied(t *testing.T) {
	path := os.Getenv("AWG_PINNED_RUNNER_ARCHIVE")
	if path == "" {
		t.Skip("set AWG_PINNED_RUNNER_ARCHIVE for the audited release-asset gate")
	}
	archive, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	image, err := InspectPinnedWindowsX64(archive)
	if err != nil {
		t.Fatal(err)
	}
	store := &discardStore{}
	if err := image.Extract(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	if !image.PinnedWindowsX64() || store.files == 0 {
		t.Fatal("pinned official archive produced no verified file stream")
	}
}

func TestPinnedLinuxX64ArchiveWhenSupplied(t *testing.T) {
	path := os.Getenv("AWG_PINNED_LINUX_RUNNER_ARCHIVE")
	if path == "" {
		t.Skip("set AWG_PINNED_LINUX_RUNNER_ARCHIVE for the audited release-asset gate")
	}
	archive, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	image, err := InspectPinnedLinuxX64(archive)
	if err != nil {
		t.Fatal(err)
	}
	if !image.PinnedLinuxX64() {
		t.Fatal("official Linux runner did not establish the production trust pin")
	}
	store := &discardStore{}
	if err := image.Extract(context.Background(), store); err != nil || store.files == 0 {
		t.Fatalf("official Linux runner extraction failed: files=%d err=%v", store.files, err)
	}
}

func TestInspectAndExtractLinuxRunner(t *testing.T) {
	archive := buildLinuxArchive(t, []linuxArchiveEntry{
		{name: "bin/Runner.Listener", content: []byte("listener"), mode: 0o755},
		{name: "config.sh", content: []byte("config"), mode: 0o755},
		{name: "run.sh", content: []byte("run"), mode: 0o755},
		{name: "bin/current", target: "Runner.Listener"},
	})
	image, err := inspectLinux(PinnedLinuxX64Version, archive)
	if err != nil {
		t.Fatal(err)
	}
	image.officialLinuxX64 = true
	store := &memoryStore{}
	if err := image.Extract(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	if store.files["bin/Runner.Listener"].String() != "listener" || store.symlinks["bin/current"] != "Runner.Listener" {
		t.Fatalf("unexpected Linux extraction: files=%v links=%v", store.files, store.symlinks)
	}
}

func TestInspectLinuxRejectsEscapesAndRuntimeState(t *testing.T) {
	for _, test := range []struct {
		name  string
		entry linuxArchiveEntry
		rule  string
	}{
		{name: "parent path", entry: linuxArchiveEntry{name: "../escape", content: []byte("x")}, rule: "entry-path-invalid"},
		{name: "absolute path", entry: linuxArchiveEntry{name: "/escape", content: []byte("x")}, rule: "entry-path-invalid"},
		{name: "reserved state", entry: linuxArchiveEntry{name: ".credentials", content: []byte("x")}, rule: "entry-path-invalid"},
		{name: "escaping link", entry: linuxArchiveEntry{name: "bin/link", target: "../../escape"}, rule: "entry-link-denied"},
	} {
		t.Run(test.name, func(t *testing.T) {
			entries := requiredLinuxEntries()
			entries = append(entries, test.entry)
			_, err := inspectLinux(PinnedLinuxX64Version, buildLinuxArchive(t, entries))
			assertPackageError(t, err, test.rule)
		})
	}
}

func TestInspectRejectsInvalidVersionDigestAndShape(t *testing.T) {
	valid := validArchive(t)
	tests := []struct {
		name    string
		version string
		digest  string
		archive []byte
		rule    string
	}{
		{name: "version", version: "latest", digest: digest(valid), archive: valid, rule: "version-invalid"},
		{name: "digest syntax", version: "2.337.0", digest: strings.Repeat("A", 64), archive: valid, rule: "digest-invalid"},
		{name: "digest mismatch", version: "2.337.0", digest: strings.Repeat("0", 64), archive: valid, rule: "archive-digest-mismatch"},
		{name: "empty", version: "2.337.0", digest: digest(nil), archive: nil, rule: "archive-size-denied"},
		{name: "not zip", version: "2.337.0", digest: digest([]byte("not zip")), archive: []byte("not zip"), rule: "archive-invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Inspect(test.version, test.digest, test.archive)
			assertPackageError(t, err, test.rule)
		})
	}
}

func TestInspectRejectsUnsafeEntries(t *testing.T) {
	tests := []struct {
		name  string
		entry archiveEntry
		rule  string
	}{
		{name: "parent", entry: archiveEntry{name: "../escape.txt"}, rule: "entry-path-invalid"},
		{name: "absolute", entry: archiveEntry{name: "/absolute.txt"}, rule: "entry-path-invalid"},
		{name: "backslash", entry: archiveEntry{name: `bin\alias.txt`}, rule: "entry-path-invalid"},
		{name: "device", entry: archiveEntry{name: "bin/CON.txt"}, rule: "entry-windows-path-denied"},
		{name: "symlink", entry: archiveEntry{name: "bin/link", mode: os.ModeSymlink | 0o777}, rule: "entry-file-denied"},
		{name: "runtime state", entry: archiveEntry{name: ".credentials", content: []byte("synthetic")}, rule: "entry-runtime-path-denied"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entries := requiredEntries()
			entries = append(entries, test.entry)
			archive := buildArchive(t, entries)
			_, err := Inspect("2.337.0", digest(archive), archive)
			assertPackageError(t, err, test.rule)
		})
	}
}

func TestInspectRejectsCaseAliasesDuplicatesAndMissingRequiredFile(t *testing.T) {
	tests := []struct {
		name    string
		entries []archiveEntry
		rule    string
	}{
		{name: "case", entries: append(requiredEntries(), archiveEntry{name: "BIN/other.dll"}), rule: "entry-case-alias-denied"},
		{name: "duplicate", entries: append(requiredEntries(), archiveEntry{name: "bin/Runner.Listener.exe"}), rule: "entry-duplicate"},
		{name: "missing", entries: []archiveEntry{{name: "bin/Runner.Listener.exe"}}, rule: "required-file-missing"},
		{name: "file parent", entries: append(requiredEntries(), archiveEntry{name: "bin", content: []byte("collision")}), rule: "entry-type-collision"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archive := buildArchive(t, test.entries)
			_, err := Inspect("2.337.0", digest(archive), archive)
			assertPackageError(t, err, test.rule)
		})
	}
}

func TestExtractFailsClosedOnCancellationAndStoreErrors(t *testing.T) {
	archive := validArchive(t)
	image, err := Inspect("2.337.0", digest(archive), archive)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	assertPackageError(t, image.Extract(cancelled, &memoryStore{}), "extract-cancelled")
	assertPackageError(t, image.Extract(context.Background(), &memoryStore{failPath: "bin"}), "directory-create-failed")
	assertPackageError(t, image.Extract(context.Background(), &memoryStore{failPath: "bin/Runner.Listener.exe"}), "file-create-failed")
}

func validArchive(t *testing.T) []byte {
	t.Helper()
	return buildArchive(t, requiredEntries())
}

func requiredEntries() []archiveEntry {
	return []archiveEntry{
		{name: "bin/Runner.Listener.exe", content: []byte("listener")},
		{name: "bin/RunnerService.exe", content: []byte("service")},
	}
}

func buildArchive(t *testing.T, entries []archiveEntry) []byte {
	t.Helper()
	var encoded bytes.Buffer
	writer := zip.NewWriter(&encoded)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		if entry.mode != 0 {
			header.SetMode(entry.mode)
		}
		destination, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := destination.Write(entry.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return encoded.Bytes()
}

type linuxArchiveEntry struct {
	name, target string
	content      []byte
	mode         int64
}

func requiredLinuxEntries() []linuxArchiveEntry {
	return []linuxArchiveEntry{
		{name: "bin/Runner.Listener", content: []byte("listener"), mode: 0o755},
		{name: "config.sh", content: []byte("config"), mode: 0o755},
		{name: "run.sh", content: []byte("run"), mode: 0o755},
	}
}

func buildLinuxArchive(t *testing.T, entries []linuxArchiveEntry) []byte {
	t.Helper()
	var encoded bytes.Buffer
	compressed := gzip.NewWriter(&encoded)
	writer := tar.NewWriter(compressed)
	for _, entry := range entries {
		typeflag := byte(tar.TypeReg)
		mode := entry.mode
		if mode == 0 {
			mode = 0o600
		}
		size := int64(len(entry.content))
		if entry.target != "" {
			typeflag = tar.TypeSymlink
			size = 0
			mode = 0o777
		}
		header := &tar.Header{Name: entry.name, Linkname: entry.target, Typeflag: typeflag, Mode: mode, Size: size}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if size > 0 {
			if _, err := writer.Write(entry.content); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return encoded.Bytes()
}

func digest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func assertPackageError(t *testing.T, err error, rule string) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Rule != rule {
		t.Fatalf("expected package error %q, got %T / %v", rule, err, err)
	}
}
