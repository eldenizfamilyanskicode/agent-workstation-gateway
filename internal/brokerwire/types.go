package brokerwire

import (
	"fmt"
	"io"

	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

type Version uint8

const CurrentVersion Version = 1

type Outcome string

const (
	OutcomeExecution Outcome = "execution"
	OutcomeRejected  Outcome = "rejected"
)

type Failure string

const (
	FailureNone                 Failure = "none"
	FailureInvalidFrame         Failure = "invalid_frame"
	FailureInvalidEnvelope      Failure = "invalid_envelope"
	FailureAuthorizationDenied  Failure = "authorization_denied"
	FailureExecutionUnavailable Failure = "execution_unavailable"
	FailureResponseUnavailable  Failure = "response_unavailable"
)

const (
	MaxPreambleBytes  = 1024
	MaxDataChunkBytes = 64 * 1024
)

type Preamble struct {
	ProtocolVersion      Version `json:"protocol_version"`
	Outcome              Outcome `json:"outcome"`
	Failure              Failure `json:"failure"`
	StdoutRetainedSHA256 string  `json:"stdout_retained_sha256"`
	StderrRetainedSHA256 string  `json:"stderr_retained_sha256"`
}

// ArtifactSink starts one response-scoped transaction. The transaction sees
// only validated relative group/path records from the execution report; no
// broker-side or request-selected destination path crosses this interface.
type ArtifactSink interface {
	Begin([]v1.ArtifactFile) (ArtifactTransaction, error)
}

// ArtifactTransaction must keep partial content unpublished until Commit.
// Abort must be safe after any Open or failed Commit call.
type ArtifactTransaction interface {
	Open(v1.ArtifactFile) (io.WriteCloser, error)
	Commit() error
	Abort() error
}

type Response struct {
	Report v1.ExecutionReport
	Stdout []byte
	Stderr []byte
}

type Error struct {
	Rule string
}

func (failure *Error) Error() string {
	return fmt.Sprintf("broker response stream failed: %s", failure.Rule)
}

type RemoteError struct {
	Failure Failure
}

func (failure *RemoteError) Error() string {
	return fmt.Sprintf("broker rejected execution: %s", failure.Failure)
}

func wireError(rule string) error {
	return &Error{Rule: rule}
}
