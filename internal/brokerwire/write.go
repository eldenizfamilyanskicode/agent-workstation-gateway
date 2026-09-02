package brokerwire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionrun"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/ipcframe"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

func WriteRejection(writer io.Writer, failure Failure) error {
	if writer == nil || failure == FailureNone {
		return wireError("rejection-invalid")
	}
	preamble, err := MarshalCanonicalPreamble(Preamble{
		ProtocolVersion: CurrentVersion,
		Outcome:         OutcomeRejected,
		Failure:         failure,
	})
	if err != nil {
		return err
	}
	if err := ipcframe.Write(writer, preamble, MaxPreambleBytes); err != nil {
		return wireError("preamble-write-failed")
	}
	return nil
}

func WriteRejectionExchange(stream io.ReadWriter, failure Failure) error {
	if stream == nil {
		return wireError("stream-required")
	}
	if err := WriteRejection(stream, failure); err != nil {
		return err
	}
	return finishServerExchange(stream)
}

// WriteExecution consumes output and always closes its artifact bundle.
func WriteExecution(writer io.Writer, output executionrun.Output) (resultErr error) {
	defer func() {
		if closeErr := output.Close(); closeErr != nil && resultErr == nil {
			resultErr = wireError("artifact-bundle-close-failed")
		}
	}()
	if writer == nil {
		return wireError("writer-required")
	}
	if err := validateOutput(output); err != nil {
		return err
	}
	preamble, err := MarshalCanonicalPreamble(Preamble{
		ProtocolVersion:      CurrentVersion,
		Outcome:              OutcomeExecution,
		Failure:              FailureNone,
		StdoutRetainedSHA256: digestBytes(output.Stdout),
		StderrRetainedSHA256: digestBytes(output.Stderr),
	})
	if err != nil {
		return err
	}
	report, err := v1.MarshalCanonicalExecutionReport(output.Report)
	if err != nil {
		return wireError("report-encode-failed")
	}
	if err := ipcframe.Write(writer, preamble, MaxPreambleBytes); err != nil {
		return wireError("preamble-write-failed")
	}
	if err := ipcframe.Write(writer, report, v1.MaxExecutionReportBytes); err != nil {
		return wireError("report-write-failed")
	}
	if err := writeBytes(writer, output.Stdout); err != nil {
		return wireError("stdout-write-failed")
	}
	if err := writeBytes(writer, output.Stderr); err != nil {
		return wireError("stderr-write-failed")
	}
	for _, file := range output.Report.Artifacts.Files {
		if err := writeArtifact(writer, output.ArtifactBundle, file); err != nil {
			return err
		}
	}
	return nil
}

func WriteExecutionExchange(stream io.ReadWriter, output executionrun.Output) error {
	if stream == nil {
		_ = output.Close()
		return wireError("stream-required")
	}
	if err := WriteExecution(stream, output); err != nil {
		return err
	}
	return finishServerExchange(stream)
}

func finishServerExchange(stream io.ReadWriter) error {
	if err := ipcframe.Write(stream, []byte(terminalMarker), MaxExchangeMarkerBytes); err != nil {
		return wireError("terminal-marker-write-failed")
	}
	acknowledgement, err := ipcframe.Read(stream, MaxExchangeMarkerBytes)
	if err != nil || !bytes.Equal(acknowledgement, []byte(acknowledgementMarker)) {
		return wireError("acknowledgement-invalid")
	}
	return nil
}

func validateOutput(output executionrun.Output) error {
	if err := v1.ValidateExecutionReport(output.Report); err != nil {
		return wireError("report-invalid")
	}
	if int64(len(output.Stdout)) != output.Report.Stdout.RetainedBytes ||
		int64(len(output.Stderr)) != output.Report.Stderr.RetainedBytes {
		return wireError("retained-length-mismatch")
	}
	if !output.Report.Stdout.Truncated && digestBytes(output.Stdout) != output.Report.Stdout.SHA256 {
		return wireError("stdout-digest-mismatch")
	}
	if !output.Report.Stderr.Truncated && digestBytes(output.Stderr) != output.Report.Stderr.SHA256 {
		return wireError("stderr-digest-mismatch")
	}
	files := output.Report.Artifacts.Files
	if (len(files) == 0) != (output.ArtifactBundle == nil) {
		return wireError("artifact-bundle-shape-invalid")
	}
	return nil
}

func writeBytes(writer io.Writer, content []byte) error {
	for len(content) > 0 {
		size := len(content)
		if size > MaxDataChunkBytes {
			size = MaxDataChunkBytes
		}
		if err := ipcframe.Write(writer, content[:size], MaxDataChunkBytes); err != nil {
			return err
		}
		content = content[size:]
	}
	return nil
}

func writeArtifact(writer io.Writer, bundle executionrun.ArtifactBundle, file v1.ArtifactFile) error {
	reader, err := bundle.Open(file.Group, file.Path)
	if err != nil {
		return wireError("artifact-open-failed")
	}
	closed := false
	defer func() {
		if !closed {
			_ = reader.Close()
		}
	}()
	hasher := sha256.New()
	buffer := make([]byte, MaxDataChunkBytes)
	remaining := file.SizeBytes
	for remaining > 0 {
		want := int64(len(buffer))
		if remaining < want {
			want = remaining
		}
		chunk := buffer[:int(want)]
		if _, err := io.ReadFull(reader, chunk); err != nil {
			return wireError("artifact-content-truncated")
		}
		if _, err := hasher.Write(chunk); err != nil {
			return wireError("artifact-hash-failed")
		}
		if err := ipcframe.Write(writer, chunk, MaxDataChunkBytes); err != nil {
			return wireError("artifact-write-failed")
		}
		remaining -= want
	}
	var extra [1]byte
	count, readErr := reader.Read(extra[:])
	if count != 0 {
		return wireError("artifact-content-overrun")
	}
	if readErr != io.EOF {
		return wireError("artifact-final-read-failed")
	}
	if hex.EncodeToString(hasher.Sum(nil)) != file.SHA256 {
		return wireError("artifact-digest-mismatch")
	}
	if err := reader.Close(); err != nil {
		return wireError("artifact-reader-close-failed")
	}
	closed = true
	return nil
}

func digestBytes(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}
