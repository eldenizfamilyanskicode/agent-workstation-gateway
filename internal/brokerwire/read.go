package brokerwire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/ipcframe"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

func ReadResponse(reader io.Reader, sink ArtifactSink) (Response, error) {
	return readResponse(reader, sink, func() error { return expectEOF(reader) })
}

// ReadResponseExchange performs the terminal acknowledgement required before
// a message-mode server disconnects. The server closes after reading the ACK,
// and the client still requires EOF before committing artifact destinations.
func ReadResponseExchange(stream io.ReadWriter, sink ArtifactSink) (Response, error) {
	if stream == nil {
		return Response{}, wireError("stream-required")
	}
	return readResponse(stream, sink, func() error { return finishClientExchange(stream) })
}

func readResponse(reader io.Reader, sink ArtifactSink, finish func() error) (Response, error) {
	if reader == nil {
		return Response{}, wireError("reader-required")
	}
	if finish == nil {
		return Response{}, wireError("finish-required")
	}
	encodedPreamble, err := ipcframe.Read(reader, MaxPreambleBytes)
	if err != nil {
		return Response{}, wireError("preamble-read-failed")
	}
	preamble, err := DecodePreamble(encodedPreamble)
	if err != nil {
		return Response{}, err
	}
	if preamble.Outcome == OutcomeRejected {
		if err := finish(); err != nil {
			return Response{}, err
		}
		return Response{}, &RemoteError{Failure: preamble.Failure}
	}

	encodedReport, err := ipcframe.Read(reader, v1.MaxExecutionReportBytes)
	if err != nil {
		return Response{}, wireError("report-read-failed")
	}
	report, err := v1.DecodeExecutionReport(encodedReport)
	if err != nil {
		return Response{}, wireError("report-invalid")
	}
	stdout, err := readBytes(reader, report.Stdout.RetainedBytes)
	if err != nil {
		return Response{}, wireError("stdout-read-failed")
	}
	if digestBytes(stdout) != preamble.StdoutRetainedSHA256 {
		return Response{}, wireError("stdout-retained-digest-mismatch")
	}
	stderr, err := readBytes(reader, report.Stderr.RetainedBytes)
	if err != nil {
		return Response{}, wireError("stderr-read-failed")
	}
	if digestBytes(stderr) != preamble.StderrRetainedSHA256 {
		return Response{}, wireError("stderr-retained-digest-mismatch")
	}

	files := report.Artifacts.Files
	if len(files) == 0 {
		if err := finish(); err != nil {
			return Response{}, err
		}
		return Response{Report: report, Stdout: stdout, Stderr: stderr}, nil
	}
	if sink == nil {
		return Response{}, wireError("artifact-sink-required")
	}
	transaction, err := sink.Begin(append([]v1.ArtifactFile(nil), files...))
	if err != nil || transaction == nil {
		return Response{}, wireError("artifact-transaction-begin-failed")
	}
	committed := false
	defer func() {
		if !committed {
			_ = transaction.Abort()
		}
	}()
	for _, file := range files {
		if err := readArtifact(reader, transaction, file); err != nil {
			return Response{}, err
		}
	}
	if err := finish(); err != nil {
		return Response{}, err
	}
	if err := transaction.Commit(); err != nil {
		return Response{}, wireError("artifact-transaction-commit-failed")
	}
	committed = true
	return Response{Report: report, Stdout: stdout, Stderr: stderr}, nil
}

func finishClientExchange(stream io.ReadWriter) error {
	terminal, err := ipcframe.Read(stream, MaxExchangeMarkerBytes)
	if err != nil || !bytes.Equal(terminal, []byte(terminalMarker)) {
		return wireError("terminal-marker-invalid")
	}
	if err := ipcframe.Write(stream, []byte(acknowledgementMarker), MaxExchangeMarkerBytes); err != nil {
		return wireError("acknowledgement-write-failed")
	}
	return expectEOF(stream)
}

func readBytes(reader io.Reader, size int64) ([]byte, error) {
	if size < 0 || size > v1.MaxOutputBytes {
		return nil, wireError("content-length-invalid")
	}
	content := make([]byte, int(size))
	offset := 0
	for offset < len(content) {
		chunk, err := ipcframe.Read(reader, MaxDataChunkBytes)
		if err != nil {
			return nil, err
		}
		if len(chunk) > len(content)-offset {
			return nil, wireError("content-chunk-overrun")
		}
		copy(content[offset:], chunk)
		offset += len(chunk)
	}
	return content, nil
}

func readArtifact(reader io.Reader, transaction ArtifactTransaction, file v1.ArtifactFile) error {
	destination, err := transaction.Open(file)
	if err != nil || destination == nil {
		return wireError("artifact-destination-open-failed")
	}
	closed := false
	defer func() {
		if !closed {
			_ = destination.Close()
		}
	}()
	hasher := sha256.New()
	remaining := file.SizeBytes
	for remaining > 0 {
		chunk, err := ipcframe.Read(reader, MaxDataChunkBytes)
		if err != nil {
			return wireError("artifact-content-truncated")
		}
		if int64(len(chunk)) > remaining {
			return wireError("artifact-content-overrun")
		}
		if _, err := hasher.Write(chunk); err != nil {
			return wireError("artifact-hash-failed")
		}
		if err := writeAll(destination, chunk); err != nil {
			return wireError("artifact-destination-write-failed")
		}
		remaining -= int64(len(chunk))
	}
	if hex.EncodeToString(hasher.Sum(nil)) != file.SHA256 {
		return wireError("artifact-digest-mismatch")
	}
	if err := destination.Close(); err != nil {
		return wireError("artifact-destination-close-failed")
	}
	closed = true
	return nil
}

func writeAll(writer io.Writer, content []byte) error {
	for len(content) > 0 {
		count, err := writer.Write(content)
		if count < 0 || count > len(content) {
			return wireError("destination-write-count-invalid")
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

func expectEOF(reader io.Reader) error {
	var extra [1]byte
	count, err := io.ReadFull(reader, extra[:])
	if count != 0 || err == nil {
		return wireError("trailing-data")
	}
	if err != io.EOF {
		return wireError("response-close-failed")
	}
	return nil
}
