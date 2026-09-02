//go:build windows

package brokeripc_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/brokerproto"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/brokersession"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/brokerwire"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionpolicy"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionrun"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/ipcframe"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/brokeripc"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

const integrationSourceSHA = "3333333333333333333333333333333333333333"

func TestSessionRunsAcrossAuthenticatedWindowsPipe(t *testing.T) {
	configuration := integrationConfiguration(t)
	launcher := &integrationLauncher{}
	runner, err := executionrun.New(launcher, nil, executionrun.Options{})
	if err != nil {
		t.Fatal(err)
	}
	session, err := brokersession.New(
		configuration,
		[]string{`SystemRoot=C:\Windows`, `WINDIR=C:\Windows`},
		integrationResolver{root: configuration.ApprovedRoots[0]},
		runner,
		integrationSourceSHA,
		brokersession.Options{},
	)
	if err != nil {
		t.Fatal(err)
	}
	server, err := brokeripc.NewServer(configuration)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	served := make(chan error, 1)
	go func() {
		connection, acceptErr := server.Accept(ctx)
		if acceptErr != nil {
			served <- acceptErr
			return
		}
		handleErr := session.Handle(ctx, connection)
		closeErr := connection.Close()
		served <- errors.Join(handleErr, closeErr)
	}()
	client, err := brokeripc.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	envelope := integrationEnvelope(t)
	encoded, err := brokerproto.MarshalCanonicalExecuteEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := ipcframe.Write(client, encoded, brokerproto.MaxExecuteEnvelopeBytes); err != nil {
		t.Fatal(err)
	}
	response, err := brokerwire.ReadResponseExchange(client, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(response.Stdout) != "pipe-response\n" || response.Report.AttemptID != envelope.AttemptID {
		t.Fatalf("authenticated session response changed: %#v / %q", response.Report, response.Stdout)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	if launcher.startCount() != 1 {
		t.Fatalf("authenticated pipe session launched %d times", launcher.startCount())
	}
}

type integrationResolver struct{ root string }

func (resolver integrationResolver) ResolveWithin(
	_ context.Context,
	_ platformpath.Platform,
	requested string,
	_ []string,
) (executionpolicy.Resolution, error) {
	return executionpolicy.Resolution{
		RequestedPath: requested, WorkingDirectory: requested, ApprovedRoot: resolver.root,
	}, nil
}

type integrationLauncher struct {
	mu     sync.Mutex
	starts int
}

func (launcher *integrationLauncher) Start(
	_ context.Context,
	_ executionrun.NativeLaunch,
	stdout io.Writer,
	_ io.Writer,
) (executionrun.Process, error) {
	launcher.mu.Lock()
	launcher.starts++
	launcher.mu.Unlock()
	_, _ = stdout.Write([]byte("pipe-response\n"))
	exit := make(chan executionrun.ProcessExit, 1)
	exit <- executionrun.ProcessExit{Code: 0}
	close(exit)
	return integrationProcess{exit: exit}, nil
}

func (launcher *integrationLauncher) startCount() int {
	launcher.mu.Lock()
	defer launcher.mu.Unlock()
	return launcher.starts
}

type integrationProcess struct {
	exit <-chan executionrun.ProcessExit
}

func (process integrationProcess) Exit() <-chan executionrun.ProcessExit { return process.exit }
func (integrationProcess) TerminateTree(context.Context) error           { return nil }

func integrationConfiguration(t *testing.T) installconfig.Config {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("current user SID: %v", err)
	}
	controlSID := user.User.Sid.String()
	if len(controlSID) < len("S-1-5-21-") || controlSID[:len("S-1-5-21-")] != "S-1-5-21-" {
		t.Skipf("current test identity is not an account SID: %s", controlSID)
	}
	configuration := installconfig.Config{
		ConfigVersion: installconfig.CurrentVersion,
		Platform:      platformpath.Windows,
		ControlIdentity: installconfig.Principal{
			Name: "awg-control", Identifier: controlSID, PrimaryGroupIdentifier: "S-1-5-32-545",
		},
		ExecutionIdentity: installconfig.Principal{
			Name: "awg-exec", Identifier: "S-1-5-21-3000-3000-3000-4300", PrimaryGroupIdentifier: "S-1-5-32-545",
		},
		ApprovedRoots: []string{`C:\Users\Alice\Projects`},
		Shells: []installconfig.ShellBinding{
			{Shell: v1.ShellPowerShell, Executable: `C:\Program Files\PowerShell\7\pwsh.exe`},
		},
		ProfileRoot: `C:\ProgramData\AgentWorkstationGateway\profile`,
		TempRoot:    `C:\ProgramData\AgentWorkstationGateway\temp`,
		PathEntries: []string{`C:\Program Files\PowerShell\7`}, Capabilities: []installconfig.Capability{},
	}
	if err := installconfig.Validate(configuration); err != nil {
		t.Fatal(err)
	}
	return configuration
}

func integrationEnvelope(t *testing.T) brokerproto.ExecuteEnvelope {
	t.Helper()
	request := v1.Request{
		ProtocolVersion: v1.Version,
		RequestID:       "request-1", SessionID: "session-1", Actor: "alice", Shell: v1.ShellPowerShell,
		WorkingDirectory: `C:\Users\Alice\Projects\demo`, Script: "Write-Output 'hello'",
		TimeoutSeconds: 30, MaxOutputBytes: 4096, Artifacts: []v1.ArtifactSelection{},
	}
	digest, err := v1.DigestRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	return brokerproto.ExecuteEnvelope{
		ProtocolVersion: brokerproto.CurrentVersion,
		Operation:       brokerproto.OperationExecute,
		AttemptID:       "attempt-1",
		AcceptedRequest: v1.AcceptedRequestRecord{
			ProtocolVersion: v1.Version, RequestID: request.RequestID, RequestDigest: digest, Request: request,
			Issue: v1.IssueProvenance{Number: 1, NodeID: "I_synthetic", SenderID: 42, SenderLogin: "alice"},
			Workflow: v1.WorkflowProvenance{
				Repository: "example/example-control", RunID: 100, RunAttempt: 1,
				EventName: "issues", EventAction: "opened", HeadSHA: strings.Repeat("1", 40),
			},
			ControlSourceSHA: strings.Repeat("2", 40), AcceptedAt: "2026-09-02T18:00:00Z",
		},
	}
}
