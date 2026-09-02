package brokersession

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/brokerproto"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/brokerwire"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionpolicy"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionrun"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/ipcframe"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

const sessionSourceSHA = "3333333333333333333333333333333333333333"

type sessionResolver struct {
	root string
	err  error
}

func (resolver sessionResolver) ResolveWithin(
	_ context.Context,
	_ platformpath.Platform,
	requested string,
	_ []string,
) (executionpolicy.Resolution, error) {
	if resolver.err != nil {
		return executionpolicy.Resolution{}, resolver.err
	}
	return executionpolicy.Resolution{
		RequestedPath: requested, WorkingDirectory: requested, ApprovedRoot: resolver.root,
	}, nil
}

type sessionLauncher struct {
	mu       sync.Mutex
	starts   int
	last     executionrun.NativeLaunch
	stdout   []byte
	stderr   []byte
	exit     executionrun.ProcessExit
	startErr error
}

func (launcher *sessionLauncher) Start(
	_ context.Context,
	launch executionrun.NativeLaunch,
	stdout io.Writer,
	stderr io.Writer,
) (executionrun.Process, error) {
	launcher.mu.Lock()
	launcher.starts++
	launcher.last = launch
	launcher.mu.Unlock()
	if launcher.startErr != nil {
		return nil, launcher.startErr
	}
	_, _ = stdout.Write(launcher.stdout)
	_, _ = stderr.Write(launcher.stderr)
	exit := make(chan executionrun.ProcessExit, 1)
	exit <- launcher.exit
	close(exit)
	return &sessionProcess{exit: exit}, nil
}

func (launcher *sessionLauncher) snapshot() (int, executionrun.NativeLaunch) {
	launcher.mu.Lock()
	defer launcher.mu.Unlock()
	return launcher.starts, launcher.last
}

type sessionProcess struct {
	exit <-chan executionrun.ProcessExit
}

func (process *sessionProcess) Exit() <-chan executionrun.ProcessExit { return process.exit }
func (*sessionProcess) TerminateTree(context.Context) error           { return nil }

type bufferTransport struct {
	input  *bytes.Reader
	output bytes.Buffer
}

func newBufferTransport(input []byte) *bufferTransport {
	scripted := append([]byte(nil), input...)
	scripted = append(scripted, testAcknowledgementFrame...)
	return &bufferTransport{input: bytes.NewReader(scripted)}
}

var testAcknowledgementFrame = []byte{0, 0, 0, 7, 'A', 'W', 'G', 1, 'A', 'C', 'K'}

func (transport *bufferTransport) ReadContext(ctx context.Context, buffer []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return transport.input.Read(buffer)
}

func (transport *bufferTransport) WriteContext(ctx context.Context, buffer []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return transport.output.Write(buffer)
}

type stalledReadTransport struct {
	mu     sync.Mutex
	first  bool
	ack    *bytes.Reader
	output bytes.Buffer
}

func (transport *stalledReadTransport) ReadContext(ctx context.Context, buffer []byte) (int, error) {
	transport.mu.Lock()
	if !transport.first {
		transport.first = true
		transport.mu.Unlock()
		<-ctx.Done()
		return 0, ctx.Err()
	}
	reader := transport.ack
	transport.mu.Unlock()
	return reader.Read(buffer)
}

func (transport *stalledReadTransport) WriteContext(ctx context.Context, buffer []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return transport.output.Write(buffer)
}

type stalledWriteTransport struct{ input *bytes.Reader }

func (transport *stalledWriteTransport) ReadContext(ctx context.Context, buffer []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return transport.input.Read(buffer)
}

func (*stalledWriteTransport) WriteContext(ctx context.Context, _ []byte) (int, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}

type stalledAcknowledgementTransport struct {
	input  *bytes.Reader
	output bytes.Buffer
}

func (transport *stalledAcknowledgementTransport) ReadContext(ctx context.Context, buffer []byte) (int, error) {
	count, err := transport.input.Read(buffer)
	if err != io.EOF {
		return count, err
	}
	<-ctx.Done()
	return 0, ctx.Err()
}

func (transport *stalledAcknowledgementTransport) WriteContext(ctx context.Context, buffer []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return transport.output.Write(buffer)
}

func TestSessionExecutesOneAuthorizedRequestAndCopiesAuthority(t *testing.T) {
	configuration := sessionConfiguration()
	safeBase := []string{`SystemRoot=C:\Windows`, `WINDIR=C:\Windows`}
	launcher := &sessionLauncher{stdout: []byte("ok\n"), stderr: []byte("notice\n")}
	session := newTestSession(t, configuration, safeBase, sessionResolver{root: configuration.ApprovedRoots[0]}, launcher, executionrun.Options{}, Options{})

	configuration.ExecutionIdentity.Identifier = "S-1-5-21-9000-9000-9000-9999"
	configuration.ApprovedRoots[0] = `C:\Other`
	configuration.Shells[0].Executable = `C:\Other\bad.exe`
	safeBase[0] = "GITHUB_TOKEN=SYNTHETIC-CONTROL-MARKER"

	envelope := sessionEnvelope(t, nil)
	transport := newBufferTransport(framedEnvelope(t, envelope))
	if err := session.Handle(context.Background(), transport); err != nil {
		t.Fatal(err)
	}
	response, err := readBufferedResponse(transport.output.Bytes(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(response.Stdout) != "ok\n" || string(response.Stderr) != "notice\n" {
		t.Fatalf("unexpected output: %q / %q", response.Stdout, response.Stderr)
	}
	if err := v1.ValidateExecutionReportBinding(envelope.AcceptedRequest, response.Report); err != nil {
		t.Fatalf("response report is not bound: %v", err)
	}
	if response.Report.AttemptID != envelope.AttemptID || response.Report.GatewaySourceSHA != sessionSourceSHA {
		t.Fatalf("response authority fields drifted: %#v", response.Report)
	}
	starts, launch := launcher.snapshot()
	if starts != 1 || launch.ExecutionIdentity.Identifier != "S-1-5-21-1000-1000-1000-1002" ||
		launch.ApprovedRoot != `C:\Users\Alice\Projects` || launch.Invocation.Executable() != `C:\Program Files\PowerShell\7\pwsh.exe` {
		t.Fatalf("installed authority was not retained: starts=%d launch=%#v", starts, launch)
	}
	for _, entry := range launch.Environment {
		if strings.Contains(entry, "SYNTHETIC-CONTROL-MARKER") || strings.HasPrefix(strings.ToUpper(entry), "GITHUB_") {
			t.Fatalf("mutated control environment reached execution: %q", entry)
		}
	}
}

func TestSessionRejectsInvalidFrameEnvelopeAndPolicyWithoutLaunching(t *testing.T) {
	configuration := sessionConfiguration()
	tests := []struct {
		name     string
		input    func(*testing.T) []byte
		resolver executionpolicy.Resolver
		failure  brokerwire.Failure
	}{
		{name: "frame", input: func(*testing.T) []byte { return []byte{0, 0, 0, 0} }, resolver: sessionResolver{root: configuration.ApprovedRoots[0]}, failure: brokerwire.FailureInvalidFrame},
		{name: "envelope", input: func(t *testing.T) []byte { return framedBytes(t, []byte(`{}`), brokerproto.MaxExecuteEnvelopeBytes) }, resolver: sessionResolver{root: configuration.ApprovedRoots[0]}, failure: brokerwire.FailureInvalidEnvelope},
		{name: "policy", input: func(t *testing.T) []byte { return framedEnvelope(t, sessionEnvelope(t, nil)) }, resolver: sessionResolver{err: errors.New("synthetic resolver denial")}, failure: brokerwire.FailureAuthorizationDenied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			launcher := &sessionLauncher{}
			session := newTestSession(t, configuration, sessionSafeBase(), test.resolver, launcher, executionrun.Options{}, Options{})
			transport := newBufferTransport(test.input(t))
			if err := session.Handle(context.Background(), transport); err != nil {
				t.Fatal(err)
			}
			_, err := readBufferedResponse(transport.output.Bytes(), nil)
			var remote *brokerwire.RemoteError
			if !errors.As(err, &remote) || remote.Failure != test.failure {
				t.Fatalf("expected %s rejection, got %T / %v", test.failure, err, err)
			}
			if starts, _ := launcher.snapshot(); starts != 0 {
				t.Fatalf("rejected request launched %d processes", starts)
			}
		})
	}
}

func TestSessionDistinguishesLifecycleReportFromInternalRunnerFailure(t *testing.T) {
	configuration := sessionConfiguration()
	envelope := sessionEnvelope(t, nil)

	launchFailure := &sessionLauncher{startErr: errors.New("synthetic launch failure")}
	session := newTestSession(t, configuration, sessionSafeBase(), sessionResolver{root: configuration.ApprovedRoots[0]}, launchFailure, executionrun.Options{}, Options{})
	transport := newBufferTransport(framedEnvelope(t, envelope))
	if err := session.Handle(context.Background(), transport); err != nil {
		t.Fatal(err)
	}
	response, err := readBufferedResponse(transport.output.Bytes(), nil)
	if err != nil || response.Report.CommandStatus != v1.CommandStatusRuntimeFailed {
		t.Fatalf("launch failure was not an execution report: %#v / %v", response, err)
	}

	regressingClock := &sessionClock{times: []time.Time{
		time.Date(2026, 9, 2, 18, 0, 1, 0, time.UTC),
		time.Date(2026, 9, 2, 18, 0, 0, 0, time.UTC),
	}}
	internalFailureLauncher := &sessionLauncher{}
	session = newTestSession(t, configuration, sessionSafeBase(), sessionResolver{root: configuration.ApprovedRoots[0]}, internalFailureLauncher, executionrun.Options{Clock: regressingClock}, Options{})
	transport = newBufferTransport(framedEnvelope(t, envelope))
	if err := session.Handle(context.Background(), transport); err != nil {
		t.Fatal(err)
	}
	_, err = readBufferedResponse(transport.output.Bytes(), nil)
	var remote *brokerwire.RemoteError
	if !errors.As(err, &remote) || remote.Failure != brokerwire.FailureExecutionUnavailable {
		t.Fatalf("internal runner failure was not rejected coarsely: %T / %v", err, err)
	}
}

func TestSessionAppliesFixedReadAndWriteDeadlines(t *testing.T) {
	configuration := sessionConfiguration()
	launcher := &sessionLauncher{}
	options := Options{RequestReadTimeout: 20 * time.Millisecond, ResponseWriteTimeout: 20 * time.Millisecond, AcknowledgementTimeout: 20 * time.Millisecond}
	session := newTestSession(t, configuration, sessionSafeBase(), sessionResolver{root: configuration.ApprovedRoots[0]}, launcher, executionrun.Options{}, options)

	readTransport := &stalledReadTransport{ack: bytes.NewReader(testAcknowledgementFrame)}
	started := time.Now()
	if err := session.Handle(context.Background(), readTransport); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("request read deadline was not bounded: %s", elapsed)
	}
	_, err := readBufferedResponse(readTransport.output.Bytes(), nil)
	var remote *brokerwire.RemoteError
	if !errors.As(err, &remote) || remote.Failure != brokerwire.FailureInvalidFrame {
		t.Fatalf("stalled read did not produce closed rejection: %T / %v", err, err)
	}

	writeTransport := &stalledWriteTransport{input: bytes.NewReader(framedEnvelope(t, sessionEnvelope(t, nil)))}
	started = time.Now()
	err = session.Handle(context.Background(), writeTransport)
	assertSessionError(t, err, "execution-response-write-failed")
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("response write deadline was not bounded: %s", elapsed)
	}
}

func TestSessionBoundsMissingTerminalAcknowledgement(t *testing.T) {
	configuration := sessionConfiguration()
	launcher := &sessionLauncher{}
	session := newTestSession(
		t,
		configuration,
		sessionSafeBase(),
		sessionResolver{root: configuration.ApprovedRoots[0]},
		launcher,
		executionrun.Options{},
		Options{AcknowledgementTimeout: 20 * time.Millisecond},
	)
	transport := &stalledAcknowledgementTransport{
		input: bytes.NewReader(framedEnvelope(t, sessionEnvelope(t, nil))),
	}
	started := time.Now()
	err := session.Handle(context.Background(), transport)
	assertSessionError(t, err, "execution-response-write-failed")
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("acknowledgement deadline was not bounded: %s", elapsed)
	}
	if starts, _ := launcher.snapshot(); starts != 1 {
		t.Fatalf("missing acknowledgement changed execution count: %d", starts)
	}
}

func TestSessionStreamsAndClosesLifecycleArtifactBundle(t *testing.T) {
	configuration := sessionConfiguration()
	content := []byte("artifact-content")
	bundle := &sessionBundle{content: content}
	collector := sessionCollector{bundle: bundle, content: content}
	launcher := &sessionLauncher{}
	runner, err := executionrun.New(launcher, collector, executionrun.Options{})
	if err != nil {
		t.Fatal(err)
	}
	session, err := New(configuration, sessionSafeBase(), sessionResolver{root: configuration.ApprovedRoots[0]}, runner, sessionSourceSHA, Options{})
	if err != nil {
		t.Fatal(err)
	}
	envelope := sessionEnvelope(t, []v1.ArtifactSelection{{Name: "logs", Paths: []string{"out.txt"}}})
	transport := newBufferTransport(framedEnvelope(t, envelope))
	if err := session.Handle(context.Background(), transport); err != nil {
		t.Fatal(err)
	}
	if !bundle.closed {
		t.Fatal("session response did not close lifecycle artifact bundle")
	}
	sink := &discardArtifactSink{}
	response, err := readBufferedResponse(transport.output.Bytes(), sink)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Report.Artifacts.Files) != 1 || !sink.transaction.committed || sink.transaction.aborted {
		t.Fatalf("artifact response was not committed: %#v / %#v", response.Report.Artifacts, sink.transaction)
	}
}

func TestSessionConstructorRejectsInvalidDependenciesAndOptions(t *testing.T) {
	configuration := sessionConfiguration()
	launcher := &sessionLauncher{}
	runner, err := executionrun.New(launcher, nil, executionrun.Options{})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		config    installconfig.Config
		safeBase  []string
		resolver  executionpolicy.Resolver
		runner    *executionrun.Runner
		sourceSHA string
		options   Options
		rule      string
	}{
		{name: "config", config: installconfig.Config{}, safeBase: sessionSafeBase(), resolver: sessionResolver{}, runner: runner, sourceSHA: sessionSourceSHA, rule: "installed-configuration-invalid"},
		{name: "resolver", config: configuration, safeBase: sessionSafeBase(), runner: runner, sourceSHA: sessionSourceSHA, rule: "execution-dependency-required"},
		{name: "runner", config: configuration, safeBase: sessionSafeBase(), resolver: sessionResolver{}, sourceSHA: sessionSourceSHA, rule: "execution-dependency-required"},
		{name: "source", config: configuration, safeBase: sessionSafeBase(), resolver: sessionResolver{}, runner: runner, sourceSHA: strings.Repeat("A", 40), rule: "gateway-source-sha-invalid"},
		{name: "environment", config: configuration, safeBase: []string{`SystemRoot=C:\Windows`}, resolver: sessionResolver{}, runner: runner, sourceSHA: sessionSourceSHA, rule: "safe-base-environment-invalid"},
		{name: "read timeout", config: configuration, safeBase: sessionSafeBase(), resolver: sessionResolver{}, runner: runner, sourceSHA: sessionSourceSHA, options: Options{RequestReadTimeout: maxRequestReadTimeout + time.Second}, rule: "request-read-timeout-invalid"},
		{name: "write timeout", config: configuration, safeBase: sessionSafeBase(), resolver: sessionResolver{}, runner: runner, sourceSHA: sessionSourceSHA, options: Options{ResponseWriteTimeout: maxResponseWriteTimeout + time.Second}, rule: "response-write-timeout-invalid"},
		{name: "ack timeout", config: configuration, safeBase: sessionSafeBase(), resolver: sessionResolver{}, runner: runner, sourceSHA: sessionSourceSHA, options: Options{AcknowledgementTimeout: maxAcknowledgementTimeout + time.Second}, rule: "acknowledgement-timeout-invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(test.config, test.safeBase, test.resolver, test.runner, test.sourceSHA, test.options)
			assertSessionError(t, err, test.rule)
		})
	}
}

type sessionClock struct {
	mu    sync.Mutex
	times []time.Time
}

func (clock *sessionClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	result := clock.times[0]
	clock.times = clock.times[1:]
	return result
}

type sessionCollector struct {
	bundle  *sessionBundle
	content []byte
}

func (collector sessionCollector) Collect(context.Context, executionrun.ArtifactPlan) (executionrun.ArtifactCollection, error) {
	return executionrun.ArtifactCollection{
		Manifest: v1.ArtifactManifest{
			Status: v1.ArtifactStatusComplete,
			Files: []v1.ArtifactFile{{
				Group: "logs", Path: "out.txt", SHA256: digestForTest(collector.content), SizeBytes: int64(len(collector.content)),
			}},
			Omissions: []v1.ArtifactOmission{},
		},
		Bundle: collector.bundle,
	}, nil
}

type sessionBundle struct {
	content []byte
	opened  bool
	closed  bool
}

func (bundle *sessionBundle) Open(group string, path string) (io.ReadCloser, error) {
	if bundle.opened || group != "logs" || path != "out.txt" {
		return nil, errors.New("synthetic artifact unavailable")
	}
	bundle.opened = true
	return io.NopCloser(bytes.NewReader(bundle.content)), nil
}

func (bundle *sessionBundle) Close() error {
	bundle.closed = true
	return nil
}

type discardArtifactSink struct{ transaction *discardArtifactTransaction }

func (sink *discardArtifactSink) Begin([]v1.ArtifactFile) (brokerwire.ArtifactTransaction, error) {
	sink.transaction = &discardArtifactTransaction{}
	return sink.transaction, nil
}

type discardArtifactTransaction struct {
	committed bool
	aborted   bool
}

func (*discardArtifactTransaction) Open(v1.ArtifactFile) (io.WriteCloser, error) {
	return nopWriteCloser{Writer: io.Discard}, nil
}

func (transaction *discardArtifactTransaction) Commit() error {
	transaction.committed = true
	return nil
}

func (transaction *discardArtifactTransaction) Abort() error {
	transaction.aborted = true
	return nil
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

func newTestSession(
	t *testing.T,
	configuration installconfig.Config,
	safeBase []string,
	resolver executionpolicy.Resolver,
	launcher *sessionLauncher,
	runnerOptions executionrun.Options,
	sessionOptions Options,
) *Session {
	t.Helper()
	runner, err := executionrun.New(launcher, nil, runnerOptions)
	if err != nil {
		t.Fatal(err)
	}
	session, err := New(configuration, safeBase, resolver, runner, sessionSourceSHA, sessionOptions)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func sessionConfiguration() installconfig.Config {
	return installconfig.Config{
		ConfigVersion: installconfig.CurrentVersion,
		Platform:      platformpath.Windows,
		ControlIdentity: installconfig.Principal{
			Name: "awg-control", Identifier: "S-1-5-21-1000-1000-1000-1001", PrimaryGroupIdentifier: "S-1-5-32-545",
		},
		ExecutionIdentity: installconfig.Principal{
			Name: "awg-exec", Identifier: "S-1-5-21-1000-1000-1000-1002", PrimaryGroupIdentifier: "S-1-5-32-545",
		},
		ApprovedRoots: []string{`C:\Users\Alice\Projects`},
		Shells: []installconfig.ShellBinding{
			{Shell: v1.ShellPowerShell, Executable: `C:\Program Files\PowerShell\7\pwsh.exe`},
		},
		ProfileRoot: `C:\ProgramData\AgentWorkstationGateway\profile`,
		TempRoot:    `C:\ProgramData\AgentWorkstationGateway\temp`,
		PathEntries: []string{`C:\Program Files\PowerShell\7`}, Capabilities: []installconfig.Capability{},
	}
}

func sessionSafeBase() []string {
	return []string{`SystemRoot=C:\Windows`, `WINDIR=C:\Windows`}
}

func sessionEnvelope(t *testing.T, artifacts []v1.ArtifactSelection) brokerproto.ExecuteEnvelope {
	t.Helper()
	if artifacts == nil {
		artifacts = []v1.ArtifactSelection{}
	}
	request := v1.Request{
		ProtocolVersion: v1.Version,
		RequestID:       "request-1", SessionID: "session-1", Actor: "alice", Shell: v1.ShellPowerShell,
		WorkingDirectory: `C:\Users\Alice\Projects\demo`, Script: "Write-Output 'hello'",
		TimeoutSeconds: 30, MaxOutputBytes: 4096, Artifacts: artifacts,
	}
	digest, err := v1.DigestRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	accepted := v1.AcceptedRequestRecord{
		ProtocolVersion: v1.Version, RequestID: request.RequestID, RequestDigest: digest, Request: request,
		Issue: v1.IssueProvenance{Number: 1, NodeID: "I_synthetic", SenderID: 42, SenderLogin: "alice"},
		Workflow: v1.WorkflowProvenance{
			Repository: "example/example-control", RunID: 100, RunAttempt: 1,
			EventName: "issues", EventAction: "opened", HeadSHA: strings.Repeat("1", 40),
		},
		ControlSourceSHA: strings.Repeat("2", 40), AcceptedAt: "2026-09-02T18:00:00Z",
	}
	envelope := brokerproto.ExecuteEnvelope{
		ProtocolVersion: brokerproto.CurrentVersion, Operation: brokerproto.OperationExecute,
		AttemptID: "attempt-1", AcceptedRequest: accepted,
	}
	if err := brokerproto.ValidateExecuteEnvelope(envelope); err != nil {
		t.Fatal(err)
	}
	return envelope
}

func framedEnvelope(t *testing.T, envelope brokerproto.ExecuteEnvelope) []byte {
	t.Helper()
	encoded, err := brokerproto.MarshalCanonicalExecuteEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return framedBytes(t, encoded, brokerproto.MaxExecuteEnvelopeBytes)
}

func framedBytes(t *testing.T, content []byte, maximum int) []byte {
	t.Helper()
	var framed bytes.Buffer
	if err := ipcframe.Write(&framed, content, maximum); err != nil {
		t.Fatal(err)
	}
	return framed.Bytes()
}

type bufferedResponseExchange struct {
	reader *bytes.Reader
	ack    bytes.Buffer
}

func (exchange *bufferedResponseExchange) Read(buffer []byte) (int, error) {
	return exchange.reader.Read(buffer)
}

func (exchange *bufferedResponseExchange) Write(buffer []byte) (int, error) {
	return exchange.ack.Write(buffer)
}

func readBufferedResponse(content []byte, sink brokerwire.ArtifactSink) (brokerwire.Response, error) {
	exchange := &bufferedResponseExchange{reader: bytes.NewReader(content)}
	response, err := brokerwire.ReadResponseExchange(exchange, sink)
	if err == nil && !bytes.Equal(exchange.ack.Bytes(), testAcknowledgementFrame) {
		return brokerwire.Response{}, errors.New("buffered response wrote an unexpected acknowledgement")
	}
	return response, err
}

func digestForTest(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func assertSessionError(t *testing.T, err error, rule string) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Rule != rule {
		t.Fatalf("expected session error %q, got %T / %v", rule, err, err)
	}
}
