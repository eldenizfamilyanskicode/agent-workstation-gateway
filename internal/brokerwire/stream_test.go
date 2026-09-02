package brokerwire

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionrun"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/ipcframe"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

type memoryBundle struct {
	files    map[string][]byte
	closed   bool
	closeErr error
}

func (bundle *memoryBundle) Open(group string, path string) (io.ReadCloser, error) {
	content, found := bundle.files[group+"\x00"+path]
	if !found {
		return nil, errors.New("synthetic missing artifact")
	}
	delete(bundle.files, group+"\x00"+path)
	return io.NopCloser(bytes.NewReader(content)), nil
}

func (bundle *memoryBundle) Close() error {
	bundle.closed = true
	return bundle.closeErr
}

type memorySink struct {
	transaction *memoryTransaction
	beginErr    error
}

func (sink *memorySink) Begin(files []v1.ArtifactFile) (ArtifactTransaction, error) {
	if sink.beginErr != nil {
		return nil, sink.beginErr
	}
	sink.transaction = &memoryTransaction{
		expected: append([]v1.ArtifactFile(nil), files...),
		content:  make(map[string]*memoryDestination),
	}
	return sink.transaction, nil
}

type memoryTransaction struct {
	expected  []v1.ArtifactFile
	content   map[string]*memoryDestination
	committed bool
	aborted   bool
	commitErr error
}

func (transaction *memoryTransaction) Open(file v1.ArtifactFile) (io.WriteCloser, error) {
	destination := &memoryDestination{}
	transaction.content[file.Group+"\x00"+file.Path] = destination
	return destination, nil
}

func (transaction *memoryTransaction) Commit() error {
	transaction.committed = transaction.commitErr == nil
	return transaction.commitErr
}

func (transaction *memoryTransaction) Abort() error {
	transaction.aborted = true
	return nil
}

type memoryDestination struct {
	bytes.Buffer
	closed bool
}

func (destination *memoryDestination) Close() error {
	destination.closed = true
	return nil
}

func TestExecutionResponseRoundTripStreamsAndCommitsArtifacts(t *testing.T) {
	stdout := bytes.Repeat([]byte("o"), MaxDataChunkBytes+17)
	stderr := []byte("retained error prefix")
	firstArtifact := bytes.Repeat([]byte("a"), MaxDataChunkBytes+3)
	secondArtifact := []byte{}
	files := []v1.ArtifactFile{
		{Group: "logs", Path: "out/large.log", SHA256: digestBytes(firstArtifact), SizeBytes: int64(len(firstArtifact))},
		{Group: "logs", Path: "out/empty.txt", SHA256: digestBytes(secondArtifact), SizeBytes: 0},
	}
	report := validWireReport(stdout, stderr, v1.ArtifactManifest{
		Status: v1.ArtifactStatusComplete, Files: files, Omissions: []v1.ArtifactOmission{},
	})
	report.Stderr.TotalBytes++
	report.Stderr.Truncated = true
	report.Stderr.SHA256 = strings.Repeat("7", 64)
	bundle := &memoryBundle{files: map[string][]byte{
		"logs\x00out/large.log": firstArtifact,
		"logs\x00out/empty.txt": secondArtifact,
	}}
	var encoded bytes.Buffer
	if err := WriteExecution(&encoded, executionrun.Output{
		Report: report, Stdout: stdout, Stderr: stderr, ArtifactBundle: bundle,
	}); err != nil {
		t.Fatal(err)
	}
	if !bundle.closed {
		t.Fatal("writer did not close the artifact bundle")
	}
	sink := &memorySink{}
	response, err := ReadResponse(&encoded, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response.Stdout, stdout) || !bytes.Equal(response.Stderr, stderr) {
		t.Fatal("retained output changed during response round trip")
	}
	if response.Report.RequestDigest != report.RequestDigest {
		t.Fatal("execution report changed during response round trip")
	}
	transaction := sink.transaction
	if transaction == nil || !transaction.committed || transaction.aborted {
		t.Fatalf("artifact transaction state is wrong: %#v", transaction)
	}
	if got := transaction.content["logs\x00out/large.log"]; got == nil || !got.closed || !bytes.Equal(got.Bytes(), firstArtifact) {
		t.Fatal("large artifact was not closed and committed exactly")
	}
	if got := transaction.content["logs\x00out/empty.txt"]; got == nil || !got.closed || got.Len() != 0 {
		t.Fatal("empty artifact was not closed and committed exactly")
	}
}

func TestEmptyExecutionAndRejectionAreDistinctTerminalResponses(t *testing.T) {
	report := validWireReport(nil, nil, v1.ArtifactManifest{
		Status: v1.ArtifactStatusNotRequested, Files: []v1.ArtifactFile{}, Omissions: []v1.ArtifactOmission{},
	})
	var execution bytes.Buffer
	if err := WriteExecution(&execution, executionrun.Output{Report: report, Stdout: []byte{}, Stderr: []byte{}}); err != nil {
		t.Fatal(err)
	}
	response, err := ReadResponse(&execution, nil)
	if err != nil || response.Report.AttemptID != report.AttemptID || len(response.Stdout) != 0 || len(response.Stderr) != 0 {
		t.Fatalf("empty execution response failed: %#v / %v", response, err)
	}

	var rejection bytes.Buffer
	if err := WriteRejection(&rejection, FailureAuthorizationDenied); err != nil {
		t.Fatal(err)
	}
	_, err = ReadResponse(&rejection, nil)
	var remote *RemoteError
	if !errors.As(err, &remote) || remote.Failure != FailureAuthorizationDenied {
		t.Fatalf("expected closed remote rejection, got %T / %v", err, err)
	}
}

func TestWriteExecutionFailsClosedAndAlwaysClosesBundle(t *testing.T) {
	report := validWireReport(nil, nil, v1.ArtifactManifest{
		Status: v1.ArtifactStatusNotRequested, Files: []v1.ArtifactFile{}, Omissions: []v1.ArtifactOmission{},
	})
	bundle := &memoryBundle{files: map[string][]byte{}}
	err := WriteExecution(io.Discard, executionrun.Output{Report: report, Stdout: []byte{}, Stderr: []byte{}, ArtifactBundle: bundle})
	assertWireError(t, err, "artifact-bundle-shape-invalid")
	if !bundle.closed {
		t.Fatal("invalid output leaked its artifact bundle")
	}

	report.Stdout.TotalBytes = 1
	report.Stdout.RetainedBytes = 1
	report.Stdout.SHA256 = digestBytes([]byte("x"))
	err = WriteExecution(io.Discard, executionrun.Output{Report: report, Stdout: []byte("y"), Stderr: []byte{}})
	assertWireError(t, err, "stdout-digest-mismatch")
}

func TestWriteExecutionRejectsArtifactTruncationOverrunAndDigestMismatch(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
		size    int64
		digest  string
		rule    string
	}{
		{name: "truncated", content: []byte("ab"), size: 3, digest: digestBytes([]byte("abc")), rule: "artifact-content-truncated"},
		{name: "overrun", content: []byte("abcd"), size: 3, digest: digestBytes([]byte("abc")), rule: "artifact-content-overrun"},
		{name: "digest", content: []byte("abc"), size: 3, digest: digestBytes([]byte("xyz")), rule: "artifact-digest-mismatch"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file := v1.ArtifactFile{Group: "logs", Path: "out.txt", SHA256: test.digest, SizeBytes: test.size}
			report := validWireReport(nil, nil, v1.ArtifactManifest{
				Status: v1.ArtifactStatusComplete, Files: []v1.ArtifactFile{file}, Omissions: []v1.ArtifactOmission{},
			})
			bundle := &memoryBundle{files: map[string][]byte{"logs\x00out.txt": test.content}}
			var encoded bytes.Buffer
			err := WriteExecution(&encoded, executionrun.Output{Report: report, Stdout: []byte{}, Stderr: []byte{}, ArtifactBundle: bundle})
			assertWireError(t, err, test.rule)
			if !bundle.closed {
				t.Fatal("artifact failure leaked the bundle")
			}
		})
	}
}

func TestReadResponseRejectsMalformedSequenceAndOutputContent(t *testing.T) {
	report := validWireReport([]byte("abc"), nil, v1.ArtifactManifest{
		Status: v1.ArtifactStatusNotRequested, Files: []v1.ArtifactFile{}, Omissions: []v1.ArtifactOmission{},
	})
	preamble := executionPreamble([]byte("abc"), nil)
	tests := []struct {
		name string
		wire func(*testing.T) []byte
		rule string
	}{
		{name: "unknown preamble field", wire: func(t *testing.T) []byte {
			return framed(t, []byte(`{"protocol_version":1,"outcome":"rejected","failure":"invalid_frame","stdout_retained_sha256":"","stderr_retained_sha256":"","secret":"synthetic"}`), MaxPreambleBytes)
		}, rule: "preamble-json-unknown-field"},
		{name: "rejection trailing", wire: func(t *testing.T) []byte {
			var wire bytes.Buffer
			if err := WriteRejection(&wire, FailureInvalidEnvelope); err != nil {
				t.Fatal(err)
			}
			wire.WriteByte(1)
			return wire.Bytes()
		}, rule: "trailing-data"},
		{name: "missing report", wire: func(t *testing.T) []byte {
			return framed(t, mustPreamble(t, preamble), MaxPreambleBytes)
		}, rule: "report-read-failed"},
		{name: "output overrun", wire: func(t *testing.T) []byte {
			var wire bytes.Buffer
			writeExecutionHeaders(t, &wire, preamble, report)
			if err := ipcframe.Write(&wire, []byte("abcd"), MaxDataChunkBytes); err != nil {
				t.Fatal(err)
			}
			return wire.Bytes()
		}, rule: "stdout-read-failed"},
		{name: "output digest", wire: func(t *testing.T) []byte {
			var wire bytes.Buffer
			writeExecutionHeaders(t, &wire, preamble, report)
			if err := ipcframe.Write(&wire, []byte("xyz"), MaxDataChunkBytes); err != nil {
				t.Fatal(err)
			}
			return wire.Bytes()
		}, rule: "stdout-retained-digest-mismatch"},
		{name: "trailing data", wire: func(t *testing.T) []byte {
			var wire bytes.Buffer
			writeExecutionHeaders(t, &wire, preamble, report)
			if err := ipcframe.Write(&wire, []byte("abc"), MaxDataChunkBytes); err != nil {
				t.Fatal(err)
			}
			wire.WriteByte(1)
			return wire.Bytes()
		}, rule: "trailing-data"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ReadResponse(bytes.NewReader(test.wire(t)), nil)
			assertWireError(t, err, test.rule)
		})
	}
}

func TestReadResponseRequiresSinkAndAbortsPartialArtifacts(t *testing.T) {
	content := []byte("artifact")
	file := v1.ArtifactFile{Group: "logs", Path: "out.txt", SHA256: digestBytes(content), SizeBytes: int64(len(content))}
	report := validWireReport(nil, nil, v1.ArtifactManifest{
		Status: v1.ArtifactStatusComplete, Files: []v1.ArtifactFile{file}, Omissions: []v1.ArtifactOmission{},
	})
	preamble := executionPreamble(nil, nil)
	var valid bytes.Buffer
	writeExecutionHeaders(t, &valid, preamble, report)
	if err := ipcframe.Write(&valid, content, MaxDataChunkBytes); err != nil {
		t.Fatal(err)
	}
	_, err := ReadResponse(bytes.NewReader(valid.Bytes()), nil)
	assertWireError(t, err, "artifact-sink-required")

	tests := []struct {
		name   string
		append func(*bytes.Buffer)
		rule   string
	}{
		{name: "digest", append: func(wire *bytes.Buffer) {
			if err := ipcframe.Write(wire, []byte("wrong!!!"), MaxDataChunkBytes); err != nil {
				t.Fatal(err)
			}
		}, rule: "artifact-digest-mismatch"},
		{name: "trailing", append: func(wire *bytes.Buffer) {
			if err := ipcframe.Write(wire, content, MaxDataChunkBytes); err != nil {
				t.Fatal(err)
			}
			wire.WriteByte(1)
		}, rule: "trailing-data"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var wire bytes.Buffer
			writeExecutionHeaders(t, &wire, preamble, report)
			test.append(&wire)
			sink := &memorySink{}
			_, err := ReadResponse(&wire, sink)
			assertWireError(t, err, test.rule)
			if sink.transaction == nil || !sink.transaction.aborted || sink.transaction.committed {
				t.Fatalf("partial artifact transaction was not aborted: %#v", sink.transaction)
			}
		})
	}
}

func TestReadResponseAbortsFailedTransactionCommit(t *testing.T) {
	content := []byte("artifact")
	file := v1.ArtifactFile{Group: "logs", Path: "out.txt", SHA256: digestBytes(content), SizeBytes: int64(len(content))}
	report := validWireReport(nil, nil, v1.ArtifactManifest{
		Status: v1.ArtifactStatusComplete, Files: []v1.ArtifactFile{file}, Omissions: []v1.ArtifactOmission{},
	})
	var wire bytes.Buffer
	writeExecutionHeaders(t, &wire, executionPreamble(nil, nil), report)
	if err := ipcframe.Write(&wire, content, MaxDataChunkBytes); err != nil {
		t.Fatal(err)
	}
	prebuilt := &memoryTransaction{
		content: make(map[string]*memoryDestination), commitErr: errors.New("synthetic commit failure"),
	}
	commitSink := fixedTransactionSink{transaction: prebuilt}
	_, err := ReadResponse(&wire, commitSink)
	assertWireError(t, err, "artifact-transaction-commit-failed")
	if !prebuilt.aborted || prebuilt.committed {
		t.Fatalf("failed commit was not aborted: %#v", prebuilt)
	}
}

type fixedTransactionSink struct{ transaction ArtifactTransaction }

func (sink fixedTransactionSink) Begin([]v1.ArtifactFile) (ArtifactTransaction, error) {
	return sink.transaction, nil
}

func validWireReport(stdout []byte, stderr []byte, artifacts v1.ArtifactManifest) v1.ExecutionReport {
	zero := int64(0)
	return v1.ExecutionReport{
		ProtocolVersion: v1.Version,
		RequestID:       "request-1", RequestDigest: strings.Repeat("1", 64), AttemptID: "attempt-1",
		GatewaySourceSHA: strings.Repeat("2", 40), CommandStatus: v1.CommandStatusCompleted, ExitCode: &zero,
		StartedAt: "2026-09-02T18:00:00Z", FinishedAt: "2026-09-02T18:00:01Z", DurationMilliseconds: 1000,
		Stdout:    v1.OutputMetadata{SHA256: digestBytes(stdout), TotalBytes: int64(len(stdout)), RetainedBytes: int64(len(stdout)), Truncated: false},
		Stderr:    v1.OutputMetadata{SHA256: digestBytes(stderr), TotalBytes: int64(len(stderr)), RetainedBytes: int64(len(stderr)), Truncated: false},
		Artifacts: artifacts,
	}
}

func executionPreamble(stdout []byte, stderr []byte) Preamble {
	return Preamble{
		ProtocolVersion: CurrentVersion, Outcome: OutcomeExecution, Failure: FailureNone,
		StdoutRetainedSHA256: digestBytes(stdout), StderrRetainedSHA256: digestBytes(stderr),
	}
}

func writeExecutionHeaders(t *testing.T, writer io.Writer, preamble Preamble, report v1.ExecutionReport) {
	t.Helper()
	if err := ipcframe.Write(writer, mustPreamble(t, preamble), MaxPreambleBytes); err != nil {
		t.Fatal(err)
	}
	encodedReport, err := v1.MarshalCanonicalExecutionReport(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := ipcframe.Write(writer, encodedReport, v1.MaxExecutionReportBytes); err != nil {
		t.Fatal(err)
	}
}

func mustPreamble(t *testing.T, preamble Preamble) []byte {
	t.Helper()
	encoded, err := MarshalCanonicalPreamble(preamble)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func framed(t *testing.T, payload []byte, maximum int) []byte {
	t.Helper()
	var encoded bytes.Buffer
	if err := ipcframe.Write(&encoded, payload, maximum); err != nil {
		t.Fatal(err)
	}
	return encoded.Bytes()
}

func assertWireError(t *testing.T, err error, rule string) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Rule != rule {
		t.Fatalf("expected wire error %q, got %T / %v", rule, err, err)
	}
}
