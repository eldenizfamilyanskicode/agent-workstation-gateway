package controlclient

import (
	"context"
	"fmt"
	"io"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/brokerproto"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/brokerwire"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/ipcframe"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

type Transport interface {
	ReadContext(context.Context, []byte) (int, error)
	WriteContext(context.Context, []byte) (int, error)
	Close() error
}

type Dialer interface {
	Dial(context.Context) (Transport, error)
}

// Destination receives streamed artifacts into private staging and publishes
// the complete response only after the client has validated its request and
// attempt binding. Abort must remove every create-owned staging object.
type Destination interface {
	brokerwire.ArtifactSink
	Publish(brokerwire.Response) error
	Abort() error
}

type Error struct {
	Rule  string
	Cause error
}

func (failure *Error) Error() string {
	return fmt.Sprintf("control exchange failed: %s", failure.Rule)
}

func (failure *Error) Unwrap() error { return failure.Cause }

func Exchange(
	ctx context.Context,
	dialer Dialer,
	accepted v1.AcceptedRequestRecord,
	attemptID string,
	destination Destination,
) (err error) {
	if ctx == nil || dialer == nil || destination == nil {
		return exchangeError("input-invalid")
	}
	published := false
	defer func() {
		if !published {
			_ = destination.Abort()
		}
	}()

	envelope := brokerproto.ExecuteEnvelope{
		ProtocolVersion: brokerproto.CurrentVersion,
		Operation:       brokerproto.OperationExecute,
		AttemptID:       attemptID,
		AcceptedRequest: accepted,
	}
	encodedEnvelope, err := brokerproto.MarshalCanonicalExecuteEnvelope(envelope)
	if err != nil {
		return exchangeError("envelope-invalid")
	}
	if err := ctx.Err(); err != nil {
		return exchangeError("cancelled")
	}
	transport, err := dialer.Dial(ctx)
	if err != nil || transport == nil {
		return exchangeError("connect-failed")
	}
	closed := false
	defer func() {
		if !closed {
			_ = transport.Close()
		}
	}()
	stream := contextStream{ctx: ctx, transport: transport}
	if err := ipcframe.Write(stream, encodedEnvelope, brokerproto.MaxExecuteEnvelopeBytes); err != nil {
		return exchangeError("request-write-failed")
	}
	response, err := brokerwire.ReadResponseExchange(stream, destination)
	if err != nil {
		return exchangeCause("response-read-failed", err)
	}
	if err := transport.Close(); err != nil {
		return exchangeError("connection-close-failed")
	}
	closed = true
	if v1.ValidateExecutionReportBinding(accepted, response.Report) != nil ||
		response.Report.AttemptID != attemptID {
		return exchangeError("response-binding-invalid")
	}
	if err := destination.Publish(response); err != nil {
		return exchangeError("response-publish-failed")
	}
	published = true
	return nil
}

type contextStream struct {
	ctx       context.Context
	transport Transport
}

func (stream contextStream) Read(buffer []byte) (int, error) {
	return stream.transport.ReadContext(stream.ctx, buffer)
}

func (stream contextStream) Write(buffer []byte) (int, error) {
	return stream.transport.WriteContext(stream.ctx, buffer)
}

func exchangeError(rule string) error {
	return &Error{Rule: rule}
}

func exchangeCause(rule string, cause error) error {
	return &Error{Rule: rule, Cause: cause}
}

var _ io.ReadWriter = contextStream{}
