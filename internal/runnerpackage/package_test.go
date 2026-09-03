package runnerpackage

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
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

type memoryWriter struct {
	bytes.Buffer
	closed bool
}

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
