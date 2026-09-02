//go:build windows

package brokeripc

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/ipcframe"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

const syntheticPeerSID = "S-1-5-21-2000-2000-2000-4242"

func TestPipePolicyIsFixedAndNarrow(t *testing.T) {
	control := mustSID(t, syntheticPeerSID)
	execution := mustSID(t, "S-1-5-21-2000-2000-2000-4243")
	descriptor, err := pipeDescriptor(control)
	if err != nil {
		t.Fatalf("build descriptor: %v", err)
	}
	if err := validatePipeDescriptor(descriptor, control, execution); err != nil {
		t.Fatalf("validate descriptor: %v", err)
	}
	if Name != `\\.\pipe\agent-workstation-gateway-v1` {
		t.Fatalf("unexpected pipe name %q", Name)
	}
	if pipeServerOpenMode != windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_FIRST_PIPE_INSTANCE|windows.FILE_FLAG_OVERLAPPED {
		t.Fatalf("unexpected server open mode %#x", pipeServerOpenMode)
	}
	if pipeMode != windows.PIPE_TYPE_MESSAGE|windows.PIPE_READMODE_MESSAGE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS {
		t.Fatalf("unexpected pipe mode %#x", pipeMode)
	}
	if pipeInstances != 1 || pipeBufferBytes != ipcframe.HeaderBytes+ipcframe.MaxFrameBytes {
		t.Fatalf("unexpected instance/buffer policy: %d/%d", pipeInstances, pipeBufferBytes)
	}
	if pipeClientAccess&windows.FILE_APPEND_DATA != 0 || pipeClientAccess&windows.WRITE_DAC != 0 || pipeClientAccess&windows.WRITE_OWNER != 0 {
		t.Fatalf("client has excess rights: %#x", pipeClientAccess)
	}
	if pipeClientAccess != 0x12019b {
		t.Fatalf("unexpected exact client access: %#x", pipeClientAccess)
	}
}

func TestPipeDescriptorRejectsExecutionAndBroadPrincipals(t *testing.T) {
	control := mustSID(t, syntheticPeerSID)
	execution := mustSID(t, "S-1-5-21-2000-2000-2000-4243")
	tests := []struct {
		name string
		sddl string
	}{
		{name: "execution", sddl: "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12019b;;;" + execution.String() + ")"},
		{name: "everyone", sddl: "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12019b;;;WD)"},
		{name: "anonymous", sddl: "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12019b;;;AN)"},
		{name: "generic write", sddl: "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GW;;;" + control.String() + ")"},
		{name: "unprotected", sddl: "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12019b;;;" + control.String() + ")"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor, err := windows.SecurityDescriptorFromString(test.sddl)
			if err != nil {
				t.Fatalf("parse descriptor: %v", err)
			}
			if err := validatePipeDescriptor(descriptor, control, execution); err == nil {
				t.Fatal("expected descriptor rejection")
			}
		})
	}
}

func TestNamedPipeRoundTripAuthenticatesCurrentPeer(t *testing.T) {
	configuration := currentPeerConfiguration(t)
	server, err := NewServer(configuration)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type acceptResult struct {
		connection *Conn
		err        error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		connection, acceptErr := server.Accept(ctx)
		accepted <- acceptResult{connection: connection, err: acceptErr}
	}()
	client, err := Dial(ctx)
	if err != nil {
		t.Fatalf("dial: %v (cause: %v)", err, errors.Unwrap(err))
	}
	defer client.Close()
	result := <-accepted
	if result.err != nil {
		t.Fatalf("accept: %v", result.err)
	}
	defer result.connection.Close()

	request := []byte(`{"request":"synthetic"}`)
	if err := ipcframe.Write(client, request, ipcframe.MaxFrameBytes); err != nil {
		t.Fatalf("write request: %v", err)
	}
	actual, err := ipcframe.Read(result.connection, ipcframe.MaxFrameBytes)
	if err != nil {
		t.Fatalf("read request: %v", err)
	}
	if string(actual) != string(request) {
		t.Fatalf("request mismatch: %q", actual)
	}
	response := []byte(`{"status":"ok"}`)
	if err := ipcframe.Write(result.connection, response, ipcframe.MaxFrameBytes); err != nil {
		t.Fatalf("write response: %v", err)
	}
	actual, err = ipcframe.Read(client, ipcframe.MaxFrameBytes)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(actual) != string(response) {
		t.Fatalf("response mismatch: %q", actual)
	}
}

func TestConnectionContextMethodsRejectCanceledIOBeforeTransfer(t *testing.T) {
	configuration := currentPeerConfiguration(t)
	server, err := NewServer(configuration)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type acceptResult struct {
		connection *Conn
		err        error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		connection, acceptErr := server.Accept(ctx)
		accepted <- acceptResult{connection: connection, err: acceptErr}
	}()
	client, err := Dial(ctx)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	result := <-accepted
	if result.err != nil {
		t.Fatalf("accept: %v", result.err)
	}
	defer result.connection.Close()

	canceled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if count, err := client.WriteContext(canceled, []byte("not-written")); count != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled write transferred data: count=%d error=%v", count, err)
	}
	if count, err := result.connection.ReadContext(canceled, make([]byte, 16)); count != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled read consumed data: count=%d error=%v", count, err)
	}

	payload := []byte("still-usable")
	if count, err := client.WriteContext(ctx, payload); err != nil || count != len(payload) {
		t.Fatalf("context write failed: count=%d error=%v", count, err)
	}
	buffer := make([]byte, len(payload))
	if count, err := result.connection.ReadContext(ctx, buffer); err != nil || count != len(payload) || string(buffer) != string(payload) {
		t.Fatalf("context read failed: count=%d content=%q error=%v", count, buffer, err)
	}
}

func TestNamedPipeRejectsImpersonatedSIDMismatch(t *testing.T) {
	configuration := currentPeerConfiguration(t)
	server, err := NewServer(configuration)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	defer server.Close()
	server.native.expectedControlSID = mustSID(t, distinctSyntheticSID(configuration.ControlIdentity.Identifier))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	accepted := make(chan error, 1)
	go func() {
		connection, acceptErr := server.Accept(ctx)
		if connection != nil {
			_ = connection.Close()
		}
		accepted <- acceptErr
	}()
	client, err := Dial(ctx)
	if err != nil {
		t.Fatalf("dial: %v (cause: %v)", err, errors.Unwrap(err))
	}
	defer client.Close()
	err = <-accepted
	var failure *Error
	if !errors.As(err, &failure) || failure.Rule != "peer-sid-mismatch" {
		t.Fatalf("expected peer SID mismatch, got %v", err)
	}
}

func TestAcceptCancellationAndCloseAreBounded(t *testing.T) {
	server, err := NewServer(currentPeerConfiguration(t))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if connection, err := server.Accept(ctx); connection != nil || err == nil {
		t.Fatalf("expected canceled accept, got connection=%v error=%v", connection, err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestFirstPipeInstanceRejectsEndpointSquatting(t *testing.T) {
	configuration := currentPeerConfiguration(t)
	first, err := NewServer(configuration)
	if err != nil {
		t.Fatalf("first server: %v", err)
	}
	defer first.Close()
	second, err := NewServer(configuration)
	if second != nil || err == nil {
		if second != nil {
			_ = second.Close()
		}
		t.Fatalf("expected second first-instance creation to fail: server=%v error=%v", second, err)
	}
	var failure *Error
	if !errors.As(err, &failure) || failure.Rule != "pipe-create-failed" {
		t.Fatalf("unexpected second-server error: %v", err)
	}
}

func TestDialCancellationWithoutServerIsBounded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	connection, err := Dial(ctx)
	if connection != nil || err == nil {
		if connection != nil {
			_ = connection.Close()
		}
		t.Fatalf("expected canceled dial: connection=%v error=%v", connection, err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline cause, got %v", err)
	}
}

func currentPeerConfiguration(t *testing.T) installconfig.Config {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("current user SID: %v", err)
	}
	control := user.User.Sid.String()
	if len(control) < len("S-1-5-21-") || control[:len("S-1-5-21-")] != "S-1-5-21-" {
		t.Skipf("current test identity is not an account SID: %s", control)
	}
	configuration := installconfig.Config{
		ConfigVersion: installconfig.CurrentVersion,
		Platform:      platformpath.Windows,
		ControlIdentity: installconfig.Principal{
			Name: "awg-control", Identifier: control, PrimaryGroupIdentifier: "S-1-5-32-545",
		},
		ExecutionIdentity: installconfig.Principal{
			Name: "awg-exec", Identifier: distinctSyntheticSID(control), PrimaryGroupIdentifier: "S-1-5-32-545",
		},
		ApprovedRoots: []string{`C:\Users\Alice\Projects`},
		Shells: []installconfig.ShellBinding{
			{Shell: v1.ShellPowerShell, Executable: `C:\Program Files\PowerShell\7\pwsh.exe`},
		},
		ProfileRoot:  `C:\ProgramData\AgentWorkstationGateway\profile`,
		TempRoot:     `C:\ProgramData\AgentWorkstationGateway\temp`,
		PathEntries:  []string{`C:\Program Files\PowerShell\7`},
		Capabilities: []installconfig.Capability{},
	}
	if err := installconfig.Validate(configuration); err != nil {
		t.Fatalf("synthetic configuration: %v", err)
	}
	return configuration
}

func distinctSyntheticSID(other string) string {
	if other == syntheticPeerSID {
		return "S-1-5-21-2000-2000-2000-4243"
	}
	return syntheticPeerSID
}

func mustSID(t *testing.T, value string) *windows.SID {
	t.Helper()
	sid, err := windows.StringToSid(value)
	if err != nil {
		t.Fatalf("parse SID: %v", err)
	}
	return sid
}
