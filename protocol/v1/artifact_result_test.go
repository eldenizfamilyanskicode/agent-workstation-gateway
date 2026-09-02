package v1

import (
	"fmt"
	"strings"
	"testing"
)

func TestValidateResultRecordArtifactStatusShapes(t *testing.T) {
	manifests := []ArtifactManifest{
		{Status: ArtifactStatusNotRequested, Files: []ArtifactFile{}, Omissions: []ArtifactOmission{}},
		{Status: ArtifactStatusComplete, Files: []ArtifactFile{validArtifactFile()}, Omissions: []ArtifactOmission{}},
		{Status: ArtifactStatusCompleteWithOmissions, Files: []ArtifactFile{}, Omissions: []ArtifactOmission{validArtifactOmission()}},
		{Status: ArtifactStatusFailed, Files: []ArtifactFile{}, Omissions: []ArtifactOmission{validArtifactOmission()}},
	}
	for _, manifest := range manifests {
		t.Run(string(manifest.Status), func(t *testing.T) {
			record := validResultRecord(t)
			record.Artifacts = manifest
			if err := ValidateResultRecord(record); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestValidateResultRecordRejectsArtifactViolations(t *testing.T) {
	tests := []struct {
		name     string
		manifest ArtifactManifest
		field    string
		rule     string
	}{
		{name: "nil arrays", manifest: ArtifactManifest{Status: ArtifactStatusNotRequested}, field: "artifacts", rule: "arrays-required"},
		{name: "unknown status", manifest: ArtifactManifest{Status: "unknown", Files: []ArtifactFile{}, Omissions: []ArtifactOmission{}}, field: "artifacts.status", rule: "unsupported-status"},
		{name: "not requested file", manifest: ArtifactManifest{Status: ArtifactStatusNotRequested, Files: []ArtifactFile{validArtifactFile()}, Omissions: []ArtifactOmission{}}, field: "artifacts.status", rule: "not-requested-requires-empty"},
		{name: "complete empty", manifest: ArtifactManifest{Status: ArtifactStatusComplete, Files: []ArtifactFile{}, Omissions: []ArtifactOmission{}}, field: "artifacts.status", rule: "complete-requires-files-only"},
		{name: "partial without omission", manifest: ArtifactManifest{Status: ArtifactStatusCompleteWithOmissions, Files: []ArtifactFile{}, Omissions: []ArtifactOmission{}}, field: "artifacts.status", rule: "status-requires-omissions"},
		{name: "unsafe file path", manifest: ArtifactManifest{Status: ArtifactStatusComplete, Files: []ArtifactFile{{Group: "results", Path: "../secret", SHA256: strings.Repeat("a", 64), SizeBytes: 1}}, Omissions: []ArtifactOmission{}}, field: "artifacts.files.path", rule: "non-canonical-segment"},
		{name: "glob file path", manifest: ArtifactManifest{Status: ArtifactStatusComplete, Files: []ArtifactFile{{Group: "results", Path: "*.txt", SHA256: strings.Repeat("a", 64), SizeBytes: 1}}, Omissions: []ArtifactOmission{}}, field: "artifacts.files.path", rule: "glob-in-file-path"},
		{name: "duplicate file", manifest: ArtifactManifest{Status: ArtifactStatusComplete, Files: []ArtifactFile{validArtifactFile(), validArtifactFile()}, Omissions: []ArtifactOmission{}}, field: "artifacts.files", rule: "duplicate-file"},
		{name: "invalid omission reason", manifest: ArtifactManifest{Status: ArtifactStatusFailed, Files: []ArtifactFile{}, Omissions: []ArtifactOmission{{Group: "results", Pattern: "*.txt", Reason: "unknown"}}}, field: "artifacts.omissions.reason", rule: "unsupported-reason"},
		{name: "duplicate omission", manifest: ArtifactManifest{Status: ArtifactStatusFailed, Files: []ArtifactFile{}, Omissions: []ArtifactOmission{validArtifactOmission(), validArtifactOmission()}}, field: "artifacts.omissions", rule: "duplicate-omission"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := validResultRecord(t)
			record.Artifacts = test.manifest
			assertProtocolError(t, ValidateResultRecord(record), ErrorKindValidation, test.field, test.rule)
		})
	}
}

func TestValidateResultRecordRejectsArtifactBounds(t *testing.T) {
	tests := []struct {
		name     string
		manifest func() ArtifactManifest
		field    string
		rule     string
	}{
		{
			name: "too many files",
			manifest: func() ArtifactManifest {
				return ArtifactManifest{Status: ArtifactStatusComplete, Files: make([]ArtifactFile, MaxArtifactFiles+1), Omissions: []ArtifactOmission{}}
			},
			field: "artifacts.files", rule: "too-many-files",
		},
		{
			name: "too many omissions",
			manifest: func() ArtifactManifest {
				return ArtifactManifest{Status: ArtifactStatusFailed, Files: []ArtifactFile{}, Omissions: make([]ArtifactOmission, MaxArtifactOmissions+1)}
			},
			field: "artifacts.omissions", rule: "too-many-omissions",
		},
		{
			name: "invalid group",
			manifest: func() ArtifactManifest {
				file := validArtifactFile()
				file.Group = "INVALID"
				return ArtifactManifest{Status: ArtifactStatusComplete, Files: []ArtifactFile{file}, Omissions: []ArtifactOmission{}}
			},
			field: "artifacts.files.group", rule: "invalid-identifier",
		},
		{
			name: "sensitive path",
			manifest: func() ArtifactManifest {
				file := validArtifactFile()
				file.Path = ".ssh/config"
				return ArtifactManifest{Status: ArtifactStatusComplete, Files: []ArtifactFile{file}, Omissions: []ArtifactOmission{}}
			},
			field: "artifacts.files.path", rule: "sensitive-segment",
		},
		{
			name: "invalid file digest",
			manifest: func() ArtifactManifest {
				file := validArtifactFile()
				file.SHA256 = strings.Repeat("F", 64)
				return ArtifactManifest{Status: ArtifactStatusComplete, Files: []ArtifactFile{file}, Omissions: []ArtifactOmission{}}
			},
			field: "artifacts.files.sha256", rule: "invalid-lower-hex",
		},
		{
			name: "file size",
			manifest: func() ArtifactManifest {
				file := validArtifactFile()
				file.SizeBytes = MaxArtifactFileBytes + 1
				return ArtifactManifest{Status: ArtifactStatusComplete, Files: []ArtifactFile{file}, Omissions: []ArtifactOmission{}}
			},
			field: "artifacts.files.size_bytes", rule: "outside-allowed-range",
		},
		{
			name: "total size",
			manifest: func() ArtifactManifest {
				files := []ArtifactFile{validArtifactFile(), validArtifactFile(), validArtifactFile()}
				for index := range files {
					files[index].Path = fmt.Sprintf("reports/result-%d.json", index)
					files[index].SizeBytes = MaxArtifactFileBytes
				}
				return ArtifactManifest{Status: ArtifactStatusComplete, Files: files, Omissions: []ArtifactOmission{}}
			},
			field: "artifacts.files", rule: "total-bytes-exceeded",
		},
		{
			name: "unsafe omission pattern",
			manifest: func() ArtifactManifest {
				omission := validArtifactOmission()
				omission.Pattern = "../reports/*.json"
				return ArtifactManifest{Status: ArtifactStatusFailed, Files: []ArtifactFile{}, Omissions: []ArtifactOmission{omission}}
			},
			field: "artifacts.omissions.pattern", rule: "non-canonical-segment",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := validResultRecord(t)
			record.Artifacts = test.manifest()
			assertProtocolError(t, ValidateResultRecord(record), ErrorKindValidation, test.field, test.rule)
		})
	}
}

func TestDecodeResultRecordRequiresArtifactSize(t *testing.T) {
	record := validResultRecord(t)
	record.Artifacts = ArtifactManifest{Status: ArtifactStatusComplete, Files: []ArtifactFile{validArtifactFile()}, Omissions: []ArtifactOmission{}}
	record.Artifacts.Files[0].SizeBytes = 0
	encoded := strings.Replace(string(mustEncodeRecord(t, record)), `,"size_bytes":0`, "", 1)
	_, err := DecodeResultRecord([]byte(encoded))
	assertProtocolError(t, err, ErrorKindDecode, "result", "missing-required-field")
}
