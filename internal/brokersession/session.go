package brokersession

import (
	"context"
	"io"
	"time"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/brokerproto"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/brokerwire"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionpolicy"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionrun"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/ipcframe"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/workloadenv"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

func New(
	configuration installconfig.Config,
	safeBaseEnvironment []string,
	resolver executionpolicy.Resolver,
	runner *executionrun.Runner,
	gatewaySourceSHA string,
	options Options,
) (*Session, error) {
	if err := installconfig.Validate(configuration); err != nil {
		return nil, sessionError("installed-configuration-invalid")
	}
	if resolver == nil || runner == nil {
		return nil, sessionError("execution-dependency-required")
	}
	if !lowerHexSourceSHA(gatewaySourceSHA) {
		return nil, sessionError("gateway-source-sha-invalid")
	}
	if _, err := workloadenv.Build(configuration, safeBaseEnvironment, workloadenv.Context{
		RequestID: "preflight-request", SessionID: "preflight-session", AttemptID: "preflight-attempt",
	}); err != nil {
		return nil, sessionError("safe-base-environment-invalid")
	}
	requestTimeout, err := boundedDuration(
		options.RequestReadTimeout, defaultRequestReadTimeout, maxRequestReadTimeout,
	)
	if err != nil {
		return nil, sessionError("request-read-timeout-invalid")
	}
	responseTimeout, err := boundedDuration(
		options.ResponseWriteTimeout, defaultResponseWriteTimeout, maxResponseWriteTimeout,
	)
	if err != nil {
		return nil, sessionError("response-write-timeout-invalid")
	}
	acknowledgementTimeout, err := boundedDuration(
		options.AcknowledgementTimeout, defaultAcknowledgementTimeout, maxAcknowledgementTimeout,
	)
	if err != nil {
		return nil, sessionError("acknowledgement-timeout-invalid")
	}
	return &Session{
		configuration:          cloneConfiguration(configuration),
		safeBaseEnvironment:    append([]string(nil), safeBaseEnvironment...),
		resolver:               resolver,
		runner:                 runner,
		gatewaySourceSHA:       gatewaySourceSHA,
		requestReadTimeout:     requestTimeout,
		responseWriteTimeout:   responseTimeout,
		acknowledgementTimeout: acknowledgementTimeout,
	}, nil
}

func (session *Session) Handle(ctx context.Context, transport ContextTransport) error {
	if session == nil || transport == nil || ctx == nil {
		return sessionError("session-input-invalid")
	}
	readContext, cancelRead := context.WithTimeout(ctx, session.requestReadTimeout)
	encodedEnvelope, err := ipcframe.Read(
		contextReader{ctx: readContext, transport: transport}, brokerproto.MaxExecuteEnvelopeBytes,
	)
	cancelRead()
	if err != nil {
		return session.reject(transport, brokerwire.FailureInvalidFrame)
	}
	envelope, err := brokerproto.DecodeExecuteEnvelope(encodedEnvelope)
	if err != nil {
		return session.reject(transport, brokerwire.FailureInvalidEnvelope)
	}
	if ctx.Err() != nil {
		return session.reject(transport, brokerwire.FailureExecutionUnavailable)
	}
	plan, err := executionpolicy.Authorize(
		ctx,
		session.configuration,
		envelope,
		session.safeBaseEnvironment,
		session.resolver,
	)
	if err != nil {
		return session.reject(transport, brokerwire.FailureAuthorizationDenied)
	}
	if ctx.Err() != nil {
		return session.reject(transport, brokerwire.FailureExecutionUnavailable)
	}
	output, err := session.runner.Run(ctx, plan, session.gatewaySourceSHA)
	if err != nil {
		_ = output.Close()
		return session.reject(transport, brokerwire.FailureExecutionUnavailable)
	}
	if v1.ValidateExecutionReportBinding(envelope.AcceptedRequest, output.Report) != nil ||
		output.Report.AttemptID != envelope.AttemptID ||
		output.Report.GatewaySourceSHA != session.gatewaySourceSHA {
		_ = output.Close()
		return session.reject(transport, brokerwire.FailureResponseUnavailable)
	}
	stream, cancelWrite := session.newExchangeStream(transport)
	defer cancelWrite()
	if err := brokerwire.WriteExecutionExchange(stream, output); err != nil {
		return sessionError("execution-response-write-failed")
	}
	return nil
}

func (session *Session) reject(transport ContextTransport, failure brokerwire.Failure) error {
	stream, cancelWrite := session.newExchangeStream(transport)
	defer cancelWrite()
	if err := brokerwire.WriteRejectionExchange(stream, failure); err != nil {
		return sessionError("rejection-write-failed")
	}
	return nil
}

func (session *Session) newExchangeStream(transport ContextTransport) (exchangeStream, context.CancelFunc) {
	writeContext, cancelWrite := context.WithTimeout(context.Background(), session.responseWriteTimeout)
	return exchangeStream{
		writeContext: writeContext,
		ackTimeout:   session.acknowledgementTimeout,
		transport:    transport,
	}, cancelWrite
}

type contextReader struct {
	ctx       context.Context
	transport ContextTransport
}

func (reader contextReader) Read(buffer []byte) (int, error) {
	return reader.transport.ReadContext(reader.ctx, buffer)
}

type contextWriter struct {
	ctx       context.Context
	transport ContextTransport
}

type exchangeStream struct {
	writeContext context.Context
	ackTimeout   time.Duration
	transport    ContextTransport
}

func (stream exchangeStream) Read(buffer []byte) (int, error) {
	ackContext, cancelAck := context.WithTimeout(context.Background(), stream.ackTimeout)
	defer cancelAck()
	return stream.transport.ReadContext(ackContext, buffer)
}

func (stream exchangeStream) Write(buffer []byte) (int, error) {
	return stream.transport.WriteContext(stream.writeContext, buffer)
}

func (writer contextWriter) Write(buffer []byte) (int, error) {
	return writer.transport.WriteContext(writer.ctx, buffer)
}

func boundedDuration(value time.Duration, fallback time.Duration, maximum time.Duration) (time.Duration, error) {
	if value == 0 {
		return fallback, nil
	}
	if value < 0 || value > maximum {
		return 0, sessionError("duration-outside-limit")
	}
	return value, nil
}

func lowerHexSourceSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func cloneConfiguration(configuration installconfig.Config) installconfig.Config {
	configuration.ApprovedRoots = append([]string{}, configuration.ApprovedRoots...)
	configuration.Shells = append([]installconfig.ShellBinding{}, configuration.Shells...)
	configuration.PathEntries = append([]string{}, configuration.PathEntries...)
	configuration.Capabilities = append([]installconfig.Capability{}, configuration.Capabilities...)
	return configuration
}

var _ io.Reader = contextReader{}
var _ io.Writer = contextWriter{}
var _ io.ReadWriter = exchangeStream{}
