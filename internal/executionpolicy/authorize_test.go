package executionpolicy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/brokerproto"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

type fakeResolver struct {
	resolution Resolution
	err        error
}

func (resolver fakeResolver) ResolveWithin(_ context.Context, _ platformpath.Platform, requested string, _ []string) (Resolution, error) {
	if resolver.err != nil {
		return Resolution{}, resolver.err
	}
	resolution := resolver.resolution
	if resolution.RequestedPath == "" {
		resolution.RequestedPath = requested
	}
	return resolution, nil
}

func TestAuthorizeBuildsFixedIdentityLaunchPlan(t *testing.T) {
	configuration := policyWindowsConfig()
	envelope := policyExecuteEnvelope(t)
	resolver := fakeResolver{resolution: Resolution{
		WorkingDirectory: `C:\Users\Alice\Projects\demo`,
		ApprovedRoot:     `C:\Users\Alice\Projects`,
	}}
	safeBase := []string{`SystemRoot=C:\Windows`, `WINDIR=C:\Windows`, `GITHUB_TOKEN=SYNTHETIC-CONTROL-MARKER`}
	plan, err := Authorize(context.Background(), configuration, envelope, safeBase, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if plan.ExecutionIdentity != configuration.ExecutionIdentity || plan.ExecutionIdentity == configuration.ControlIdentity {
		t.Fatal("launch plan did not select the fixed execution identity")
	}
	if plan.Executable != configuration.Shells[0].Executable || plan.WorkingDirectory != resolver.resolution.WorkingDirectory {
		t.Fatalf("unexpected launch target: %#v", plan)
	}
	if plan.ApprovedRoot != resolver.resolution.ApprovedRoot {
		t.Fatal("launch plan lost the native-approved root binding")
	}
	for _, entry := range plan.Environment {
		if strings.HasPrefix(strings.ToUpper(entry), "GITHUB_TOKEN=") {
			t.Fatal("control credential marker name reached workload environment")
		}
	}
	if plan.RequestDigest != envelope.AcceptedRequest.RequestDigest || plan.Script != envelope.AcceptedRequest.Request.Script {
		t.Fatal("launch plan lost accepted request binding")
	}
}

func TestAuthorizeFailsClosedOnPolicyAndResolverErrors(t *testing.T) {
	tests := []struct {
		name     string
		alter    func(*installconfig.Config, *brokerproto.ExecuteEnvelope, *fakeResolver)
		field    string
		rule     string
		safeBase []string
	}{
		{name: "invalid config", alter: func(config *installconfig.Config, _ *brokerproto.ExecuteEnvelope, _ *fakeResolver) {
			config.ExecutionIdentity = config.ControlIdentity
		}, field: "config", rule: "invalid-installation-config"},
		{name: "invalid envelope", alter: func(_ *installconfig.Config, envelope *brokerproto.ExecuteEnvelope, _ *fakeResolver) {
			envelope.Operation = "admin"
		}, field: "envelope", rule: "invalid-execute-envelope"},
		{name: "platform mismatch", alter: func(_ *installconfig.Config, envelope *brokerproto.ExecuteEnvelope, _ *fakeResolver) {
			rebindRequest(t, envelope, "/home/alice/projects")
		}, field: "working_directory", rule: "platform-mismatch"},
		{name: "shell not configured", alter: func(_ *installconfig.Config, envelope *brokerproto.ExecuteEnvelope, _ *fakeResolver) {
			rebindShell(t, envelope, v1.ShellCmd)
		}, field: "shell", rule: "not-configured"},
		{name: "resolver denial", alter: func(_ *installconfig.Config, _ *brokerproto.ExecuteEnvelope, resolver *fakeResolver) {
			resolver.err = errors.New("synthetic denial")
		}, field: "working_directory", rule: "resolution-denied"},
		{name: "resolver request mismatch", alter: func(_ *installconfig.Config, _ *brokerproto.ExecuteEnvelope, resolver *fakeResolver) {
			resolver.resolution.RequestedPath = `C:\Other`
		}, field: "working_directory", rule: "resolver-request-mismatch"},
		{name: "unconfigured root", alter: func(_ *installconfig.Config, _ *brokerproto.ExecuteEnvelope, resolver *fakeResolver) {
			resolver.resolution.ApprovedRoot = `C:\Other`
		}, field: "approved_root", rule: "not-configured"},
		{name: "outside root", alter: func(_ *installconfig.Config, _ *brokerproto.ExecuteEnvelope, resolver *fakeResolver) {
			resolver.resolution.WorkingDirectory = `C:\Windows`
		}, field: "working_directory", rule: "outside-approved-root"},
		{name: "invalid resolved path", alter: func(_ *installconfig.Config, _ *brokerproto.ExecuteEnvelope, resolver *fakeResolver) {
			resolver.resolution.WorkingDirectory = `C:\Users\Alice\Projects\..\Admin`
		}, field: "working_directory", rule: "resolver-returned-invalid-path"},
		{name: "environment failure", alter: func(_ *installconfig.Config, _ *brokerproto.ExecuteEnvelope, _ *fakeResolver) {}, field: "environment", rule: "construction-failed", safeBase: []string{`SystemRoot=C:\Windows`}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration := policyWindowsConfig()
			envelope := policyExecuteEnvelope(t)
			resolver := fakeResolver{resolution: Resolution{
				WorkingDirectory: `C:\Users\Alice\Projects\demo`, ApprovedRoot: `C:\Users\Alice\Projects`,
			}}
			test.alter(&configuration, &envelope, &resolver)
			safeBase := test.safeBase
			if safeBase == nil {
				safeBase = []string{`SystemRoot=C:\Windows`, `WINDIR=C:\Windows`}
			}
			_, err := Authorize(context.Background(), configuration, envelope, safeBase, resolver)
			assertPolicyError(t, err, test.field, test.rule)
		})
	}
}

func TestAuthorizeCopiesRequestAndConfigurationSlices(t *testing.T) {
	configuration := policyWindowsConfig()
	envelope := policyExecuteEnvelope(t)
	envelope.AcceptedRequest.Request.Artifacts = []v1.ArtifactSelection{{Name: "results", Paths: []string{"reports/*.json"}}}
	envelope.AcceptedRequest.RequestDigest = mustPolicyRequestDigest(t, envelope.AcceptedRequest.Request)
	resolver := fakeResolver{resolution: Resolution{
		WorkingDirectory: `C:\Users\Alice\Projects\demo`, ApprovedRoot: `C:\Users\Alice\Projects`,
	}}
	plan, err := Authorize(context.Background(), configuration, envelope, []string{`SystemRoot=C:\Windows`, `WINDIR=C:\Windows`}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	envelope.AcceptedRequest.Request.Artifacts[0].Paths[0] = "changed"
	configuration.Capabilities = append(configuration.Capabilities, installconfig.CapabilityDocker)
	if plan.Artifacts[0].Paths[0] != "reports/*.json" || len(plan.Capabilities) != 0 {
		t.Fatal("launch plan aliases mutable caller slices")
	}
}

func policyWindowsConfig() installconfig.Config {
	return installconfig.Config{
		ConfigVersion: installconfig.CurrentVersion, Platform: platformpath.Windows,
		ControlIdentity:   installconfig.Principal{Name: "awg-control", Identifier: "S-1-5-21-1000-1000-1000-1001", PrimaryGroupIdentifier: "S-1-5-32-545"},
		ExecutionIdentity: installconfig.Principal{Name: "awg-exec", Identifier: "S-1-5-21-1000-1000-1000-1002", PrimaryGroupIdentifier: "S-1-5-32-545"},
		ApprovedRoots:     []string{`C:\Users\Alice\Projects`},
		Shells:            []installconfig.ShellBinding{{Shell: v1.ShellPwsh, Executable: `C:\Program Files\PowerShell\7\pwsh.exe`}},
		ProfileRoot:       `C:\ProgramData\AWG\Profiles\Exec`, TempRoot: `C:\ProgramData\AWG\Temp`,
		PathEntries: []string{`C:\Program Files\PowerShell\7`, `C:\Windows\System32`}, Capabilities: []installconfig.Capability{},
	}
}

func policyExecuteEnvelope(t *testing.T) brokerproto.ExecuteEnvelope {
	t.Helper()
	request := v1.Request{
		ProtocolVersion: v1.Version, RequestID: "req-000001", SessionID: "example-session", Actor: "codex",
		Shell: v1.ShellPwsh, WorkingDirectory: `C:\Users\Alice\Projects\demo`, Script: "Get-ChildItem\n",
		TimeoutSeconds: 900, MaxOutputBytes: 1024 * 1024, Artifacts: []v1.ArtifactSelection{},
	}
	digest := mustPolicyRequestDigest(t, request)
	return brokerproto.ExecuteEnvelope{
		ProtocolVersion: brokerproto.CurrentVersion, Operation: brokerproto.OperationExecute, AttemptID: "attempt-000001",
		AcceptedRequest: v1.AcceptedRequestRecord{
			ProtocolVersion: v1.Version, RequestID: request.RequestID, RequestDigest: digest, Request: request,
			Issue: v1.IssueProvenance{Number: 42, NodeID: "ISSUE_node_42", SenderID: 1001, SenderLogin: "alice-example"},
			Workflow: v1.WorkflowProvenance{
				Repository: "alice/example-control", RunID: 9001, RunAttempt: 1,
				EventName: "issues", EventAction: "opened", HeadSHA: strings.Repeat("a", 40),
			},
			ControlSourceSHA: strings.Repeat("b", 40), AcceptedAt: "2026-09-02T18:00:00Z",
		},
	}
}

func rebindRequest(t *testing.T, envelope *brokerproto.ExecuteEnvelope, workingDirectory string) {
	t.Helper()
	envelope.AcceptedRequest.Request.WorkingDirectory = workingDirectory
	envelope.AcceptedRequest.RequestDigest = mustPolicyRequestDigest(t, envelope.AcceptedRequest.Request)
}

func rebindShell(t *testing.T, envelope *brokerproto.ExecuteEnvelope, shell v1.Shell) {
	t.Helper()
	envelope.AcceptedRequest.Request.Shell = shell
	envelope.AcceptedRequest.RequestDigest = mustPolicyRequestDigest(t, envelope.AcceptedRequest.Request)
}

func mustPolicyRequestDigest(t *testing.T, request v1.Request) string {
	t.Helper()
	digest, err := v1.DigestRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func assertPolicyError(t *testing.T, err error, field string, rule string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected policy error %s/%s", field, rule)
	}
	var authorizationFailure *Error
	if !errors.As(err, &authorizationFailure) {
		t.Fatalf("expected policy error, got %T: %v", err, err)
	}
	if authorizationFailure.Field != field || authorizationFailure.Rule != rule {
		t.Fatalf("expected %s/%s, got %s/%s", field, rule, authorizationFailure.Field, authorizationFailure.Rule)
	}
}
