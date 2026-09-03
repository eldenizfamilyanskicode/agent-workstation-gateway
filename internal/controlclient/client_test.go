package controlclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/brokerproto"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/brokerwire"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionrun"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/ipcframe"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

type dialerFunc func(context.Context) (Transport, error)

func (function dialerFunc) Dial(ctx context.Context) (Transport, error) { return function(ctx) }

type pipeTransport struct{ net.Conn }

func (transport pipeTransport) ReadContext(ctx context.Context, buffer []byte) (int, error) {
	return transport.Read(buffer)
}

func (transport pipeTransport) WriteContext(ctx context.Context, buffer []byte) (int, error) {
	return transport.Write(buffer)
}

type memoryDestination struct {
	mu          sync.Mutex
	published   bool
	aborted     bool
	response    brokerwire.Response
	publishErr  error
	transaction *memoryArtifactTransaction
}

func (destination *memoryDestination) Begin(files []v1.ArtifactFile) (brokerwire.ArtifactTransaction, error) {
	destination.mu.Lock()
	defer destination.mu.Unlock()
	destination.transaction = &memoryArtifactTransaction{expected: append([]v1.ArtifactFile(nil), files...)}
	return destination.transaction, nil
}

func (destination *memoryDestination) Publish(response brokerwire.Response) error {
	destination.mu.Lock()
	defer destination.mu.Unlock()
	if destination.publishErr != nil {
		return destination.publishErr
	}
	destination.response = response
	destination.published = true
	return nil
}

func (destination *memoryDestination) Abort() error {
	destination.mu.Lock()
	defer destination.mu.Unlock()
	destination.aborted = true
	return nil
}

type memoryArtifactTransaction struct {
	expected  []v1.ArtifactFile
	committed bool
	aborted   bool
}

func (*memoryArtifactTransaction) Open(v1.ArtifactFile) (io.WriteCloser, error) {
	return nopWriteCloser{Writer: io.Discard}, nil
}

func (transaction *memoryArtifactTransaction) Commit() error {
	transaction.committed = true
	return nil
}

func (transaction *memoryArtifactTransaction) Abort() error {
	transaction.aborted = true
	return nil
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

func TestExchangeWritesCanonicalEnvelopeAndPublishesBoundResponse(t *testing.T) {
	accepted := validAccepted(t)
	report := validReport(accepted, "attempt-000001")
	server, client := net.Pipe()
	serverResult := make(chan error, 1)
	go func() {
		defer server.Close()
		encoded, err := ipcframe.Read(server, brokerproto.MaxExecuteEnvelopeBytes)
		if err != nil {
			serverResult <- err
			return
		}
		envelope, err := brokerproto.DecodeExecuteEnvelope(encoded)
		if err != nil || envelope.AttemptID != report.AttemptID ||
			envelope.AcceptedRequest.RequestDigest != accepted.RequestDigest {
			serverResult <- errors.New("canonical envelope changed")
			return
		}
		serverResult <- brokerwire.WriteExecutionExchange(server, executionrun.Output{
			Report: report, Stdout: []byte("synthetic output"), Stderr: []byte{},
		})
	}()

	destination := &memoryDestination{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := Exchange(ctx, dialerFunc(func(context.Context) (Transport, error) {
		return pipeTransport{Conn: client}, nil
	}), accepted, report.AttemptID, destination)
	if err != nil {
		t.Fatalf("%v; cause: %v; server: %v", err, errors.Unwrap(err), <-serverResult)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
	if !destination.published || destination.aborted ||
		!bytes.Equal(destination.response.Stdout, []byte("synthetic output")) {
		t.Fatalf("response destination state changed: %#v", destination)
	}
}

func TestExchangeRejectsBindingFailureBeforePublication(t *testing.T) {
	accepted := validAccepted(t)
	report := validReport(accepted, "attempt-000001")
	report.RequestID = "another-request"
	destination, err := exchangeWithReport(t, accepted, "attempt-000001", report)
	assertExchangeError(t, err, "response-binding-invalid")
	if destination.published || !destination.aborted {
		t.Fatalf("binding failure was published: %#v", destination)
	}
}

func TestExchangeRejectsAttemptMismatchBeforePublication(t *testing.T) {
	accepted := validAccepted(t)
	report := validReport(accepted, "attempt-000002")
	destination, err := exchangeWithReport(t, accepted, "attempt-000001", report)
	assertExchangeError(t, err, "response-binding-invalid")
	if destination.published || !destination.aborted {
		t.Fatalf("attempt mismatch was published: %#v", destination)
	}
}

func TestExchangeFailsClosedAtEveryOuterStage(t *testing.T) {
	accepted := validAccepted(t)
	tests := []struct {
		name        string
		ctx         context.Context
		dialer      Dialer
		accepted    v1.AcceptedRequestRecord
		attemptID   string
		destination *memoryDestination
		rule        string
	}{
		{name: "cancelled", ctx: cancelledContext(), dialer: failingDialer(errors.New("must not dial")), accepted: accepted, attemptID: "attempt-1", destination: &memoryDestination{}, rule: "cancelled"},
		{name: "connect", ctx: context.Background(), dialer: failingDialer(errors.New("synthetic")), accepted: accepted, attemptID: "attempt-1", destination: &memoryDestination{}, rule: "connect-failed"},
		{name: "invalid envelope", ctx: context.Background(), dialer: failingDialer(errors.New("must not dial")), accepted: accepted, attemptID: "../attempt", destination: &memoryDestination{}, rule: "envelope-invalid"},
		{name: "publish", ctx: context.Background(), accepted: accepted, attemptID: "attempt-1", destination: &memoryDestination{publishErr: errors.New("synthetic")}, rule: "response-publish-failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "publish" {
				report := validReport(accepted, test.attemptID)
				server, client := net.Pipe()
				test.dialer = dialerFunc(func(context.Context) (Transport, error) { return pipeTransport{Conn: client}, nil })
				go serveReport(server, report)
			}
			err := Exchange(test.ctx, test.dialer, test.accepted, test.attemptID, test.destination)
			assertExchangeError(t, err, test.rule)
			if test.destination.published || !test.destination.aborted {
				t.Fatalf("failed exchange destination state changed: %#v", test.destination)
			}
		})
	}
}

func TestExchangeTurnsRemoteRejectionIntoCoarseFailure(t *testing.T) {
	accepted := validAccepted(t)
	server, client := net.Pipe()
	go func() {
		defer server.Close()
		_, _ = ipcframe.Read(server, brokerproto.MaxExecuteEnvelopeBytes)
		_ = brokerwire.WriteRejectionExchange(server, brokerwire.FailureAuthorizationDenied)
	}()
	destination := &memoryDestination{}
	err := Exchange(context.Background(), dialerFunc(func(context.Context) (Transport, error) {
		return pipeTransport{Conn: client}, nil
	}), accepted, "attempt-1", destination)
	assertExchangeError(t, err, "response-read-failed")
	if destination.published || !destination.aborted {
		t.Fatalf("remote rejection destination state changed: %#v", destination)
	}
}

func exchangeWithReport(
	t *testing.T,
	accepted v1.AcceptedRequestRecord,
	attemptID string,
	report v1.ExecutionReport,
) (*memoryDestination, error) {
	t.Helper()
	server, client := net.Pipe()
	go func() {
		defer server.Close()
		_, _ = ipcframe.Read(server, brokerproto.MaxExecuteEnvelopeBytes)
		_ = brokerwire.WriteExecutionExchange(server, executionrun.Output{Report: report, Stdout: []byte("synthetic output"), Stderr: []byte{}})
	}()
	destination := &memoryDestination{}
	err := Exchange(context.Background(), dialerFunc(func(context.Context) (Transport, error) {
		return pipeTransport{Conn: client}, nil
	}), accepted, attemptID, destination)
	return destination, err
}

func serveReport(server net.Conn, report v1.ExecutionReport) {
	defer server.Close()
	_, _ = ipcframe.Read(server, brokerproto.MaxExecuteEnvelopeBytes)
	_ = brokerwire.WriteExecutionExchange(server, executionrun.Output{Report: report, Stdout: []byte("synthetic output"), Stderr: []byte{}})
}

func failingDialer(failure error) Dialer {
	return dialerFunc(func(context.Context) (Transport, error) { return nil, failure })
}

func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func validAccepted(t *testing.T) v1.AcceptedRequestRecord {
	t.Helper()
	request := v1.Request{
		ProtocolVersion: v1.Version, RequestID: "request-1", SessionID: "session-1", Actor: "codex",
		Shell: v1.ShellPwsh, WorkingDirectory: `C:\Users\Alice\Projects\demo`, Script: "Get-Date\n",
		TimeoutSeconds: 60, MaxOutputBytes: 1024, Artifacts: []v1.ArtifactSelection{},
	}
	digest, err := v1.DigestRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	return v1.AcceptedRequestRecord{
		ProtocolVersion: v1.Version, RequestID: request.RequestID, RequestDigest: digest, Request: request,
		Issue: v1.IssueProvenance{Number: 42, NodeID: "ISSUE_node_42", SenderID: 1001, SenderLogin: "alice-example"},
		Workflow: v1.WorkflowProvenance{
			Repository: "alice/example-control", RunID: 9001, RunAttempt: 1,
			EventName: "issues", EventAction: "opened", HeadSHA: strings.Repeat("a", 40),
		},
		ControlSourceSHA: strings.Repeat("b", 40), AcceptedAt: "2026-09-03T00:00:00Z",
	}
}

func validReport(accepted v1.AcceptedRequestRecord, attemptID string) v1.ExecutionReport {
	exitCode := int64(0)
	stdout := []byte("synthetic output")
	return v1.ExecutionReport{
		ProtocolVersion: v1.Version, RequestID: accepted.RequestID, RequestDigest: accepted.RequestDigest,
		AttemptID: attemptID, GatewaySourceSHA: strings.Repeat("c", 40), CommandStatus: v1.CommandStatusCompleted,
		ExitCode: &exitCode, StartedAt: "2026-09-03T00:00:01Z", FinishedAt: "2026-09-03T00:00:02Z",
		DurationMilliseconds: 1000,
		Stdout:               v1.OutputMetadata{SHA256: digest(stdout), TotalBytes: int64(len(stdout)), RetainedBytes: int64(len(stdout))},
		Stderr:               v1.OutputMetadata{SHA256: digest(nil), TotalBytes: 0, RetainedBytes: 0},
		Artifacts:            v1.ArtifactManifest{Status: v1.ArtifactStatusNotRequested, Files: []v1.ArtifactFile{}, Omissions: []v1.ArtifactOmission{}},
	}
}

func digest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func assertExchangeError(t *testing.T, err error, rule string) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Rule != rule {
		t.Fatalf("expected exchange error %q, got %T / %v", rule, err, err)
	}
}
