package githubcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

var testToken = []byte("synthetic-hosted-token")

func TestPublishAcceptedVerifiesPrivateAndCreatesOnce(t *testing.T) {
	record := githubAccepted(t)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.Header.Get("Authorization") != "Bearer "+string(testToken) {
			t.Error("authorization header missing")
		}
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/repos/alice/example-control":
			_, _ = writer.Write([]byte(`{"full_name":"alice/example-control","private":true,"visibility":"private"}`))
		case request.Method == http.MethodPut && request.URL.Path == "/repos/alice/example-control/contents/ledger/requests/req-1/accepted.json":
			var payload createFileRequest
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
				t.Error(err)
			}
			content, err := base64.StdEncoding.DecodeString(payload.Content)
			if err != nil {
				t.Error(err)
			}
			decoded, err := v1.DecodeAcceptedRequestRecord(content)
			if err != nil || decoded.RequestID != record.RequestID {
				t.Errorf("invalid published record: %v", err)
			}
			writer.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("unexpected request: %s %s", request.Method, request.URL.Path)
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client, err := newClient(server.URL, testToken, "alice/example-control", server.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.PublishAccepted(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("unexpected request count: %d", requests)
	}
}

func TestVerifyPrivateRejectsPublicRepository(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte(`{"full_name":"alice/example-control","private":false,"visibility":"public"}`))
	}))
	defer server.Close()
	client, err := newClient(server.URL, testToken, "alice/example-control", server.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.VerifyPrivate(context.Background()); err == nil || !strings.Contains(err.Error(), "private-repository-required") {
		t.Fatalf("public repository was accepted: %v", err)
	}
}

func TestPublishConflictFailsClosed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet {
			_, _ = writer.Write([]byte(`{"full_name":"alice/example-control","private":true,"visibility":"private"}`))
			return
		}
		writer.WriteHeader(http.StatusUnprocessableEntity)
	}))
	defer server.Close()
	client, err := newClient(server.URL, testToken, "alice/example-control", server.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.PublishAccepted(context.Background(), githubAccepted(t)); err == nil || !strings.Contains(err.Error(), "create-once-conflict") {
		t.Fatalf("conflict was not closed: %v", err)
	}
}

func TestClientRejectsUnsafeInputsAndClearsToken(t *testing.T) {
	for _, test := range []struct {
		base, repository string
		token            []byte
	}{
		{base: "http://api.example", repository: "alice/example-control", token: testToken},
		{base: "https://api.example/path", repository: "alice/example-control", token: testToken},
		{base: "https://api.example", repository: "alice/example.git", token: testToken},
		{base: "https://api.example", repository: "alice/example-control", token: []byte("short")},
	} {
		if _, err := newClient(test.base, test.token, test.repository, http.DefaultClient, false); err == nil {
			t.Fatalf("unsafe client accepted: %#v", test)
		}
	}
	client, err := newClient("https://api.example", testToken, "alice/example-control", http.DefaultClient, false)
	if err != nil {
		t.Fatal(err)
	}
	owned := client.token
	client.Close()
	if client.token != nil {
		t.Fatal("token retained after close")
	}
	for _, value := range owned {
		if value != 0 {
			t.Fatal("owned token copy was not cleared")
		}
	}
}

func TestExclusiveRepositoryControlFileAndRunnerTokens(t *testing.T) {
	createdFile := false
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/repos/alice/example-control":
			_, _ = writer.Write([]byte(`{"full_name":"alice/example-control","private":true,"visibility":"private","owner":{"login":"alice"}}`))
		case "/user":
			_, _ = writer.Write([]byte(`{"login":"alice"}`))
		case "/repos/alice/example-control/collaborators":
			_, _ = writer.Write([]byte(`[{"login":"alice"}]`))
		case "/repos/alice/example-control/contents/control-version.json":
			if request.Method == http.MethodGet {
				writer.WriteHeader(http.StatusNotFound)
				return
			}
			createdFile = request.Method == http.MethodPut
			writer.WriteHeader(http.StatusCreated)
		case "/repos/alice/example-control/actions/runners/registration-token":
			writer.WriteHeader(http.StatusCreated)
			_, _ = writer.Write([]byte(`{"token":"synthetic-registration-token"}`))
		default:
			t.Errorf("unexpected request: %s %s", request.Method, request.URL.String())
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client, err := newClient(server.URL, testToken, "alice/example-control", server.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	created, err := client.EnsureControlFile(context.Background(), "control-version.json", []byte(`{"schema_version":1}`))
	if err != nil || !created || !createdFile {
		t.Fatalf("control file was not created: created=%v requested=%v err=%v", created, createdFile, err)
	}
	token, err := client.RegistrationToken(context.Background())
	if err != nil || string(token) != "synthetic-registration-token" {
		t.Fatalf("registration token unavailable: %v", err)
	}
}

func TestExclusiveRepositoryRejectsUnexpectedReader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/repos/alice/example-control":
			_, _ = writer.Write([]byte(`{"full_name":"alice/example-control","private":true,"visibility":"private","owner":{"login":"alice"}}`))
		case "/user":
			_, _ = writer.Write([]byte(`{"login":"alice"}`))
		case "/repos/alice/example-control/collaborators":
			_, _ = writer.Write([]byte(`[{"login":"alice"},{"login":"mallory"}]`))
		}
	}))
	defer server.Close()
	client, err := newClient(server.URL, testToken, "alice/example-control", server.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.VerifyExclusivePrivate(context.Background()); err == nil || !strings.Contains(err.Error(), "unexpected-repository-reader") {
		t.Fatalf("unexpected reader was accepted: %v", err)
	}
}

func TestCreatePersonalPrivateRepository(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/user" {
			_, _ = writer.Write([]byte(`{"login":"alice"}`))
			return
		}
		if request.URL.Path != "/user/repos" || request.Method != http.MethodPost {
			t.Errorf("unexpected create request: %s %s", request.Method, request.URL.Path)
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte(`{"full_name":"alice/example-control","private":true,"visibility":"private"}`))
	}))
	defer server.Close()
	client, err := newClient(server.URL, testToken, "alice/example-control", server.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.CreatePersonalPrivate(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestUninstallPreflightBindsRunnerAndControlContent(t *testing.T) {
	controlContent := []byte("synthetic fixed control content")
	digest := sha256.Sum256(controlContent)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/repos/alice/example-control":
			_, _ = writer.Write([]byte(`{"full_name":"alice/example-control","private":true,"visibility":"private","owner":{"login":"alice"}}`))
		case "/user":
			_, _ = writer.Write([]byte(`{"login":"alice"}`))
		case "/repos/alice/example-control/collaborators":
			_, _ = writer.Write([]byte(`[{"login":"alice"}]`))
		case "/repos/alice/example-control/actions/runners":
			_, _ = writer.Write([]byte(`{"total_count":1,"runners":[{"id":7,"name":"awg-windows-x64","labels":[{"name":"agent-workstation-gateway"}]}]}`))
		case "/repos/alice/example-control/contents/control-version.json":
			response := contentResponse{Type: "file", Encoding: "base64", Content: base64.StdEncoding.EncodeToString(controlContent), SHA: "git-blob-sha"}
			_ = json.NewEncoder(writer).Encode(response)
		default:
			t.Errorf("unexpected preflight request: %s", request.URL.String())
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client, err := newClient(server.URL, testToken, "alice/example-control", server.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.VerifyRunner(context.Background(), "awg-windows-x64"); err != nil {
		t.Fatal(err)
	}
	if err := client.VerifyOwnedControlFile(context.Background(), "control-version.json", hex.EncodeToString(digest[:])); err != nil {
		t.Fatal(err)
	}
	if err := client.VerifyOwnedControlFile(context.Background(), "control-version.json", strings.Repeat("0", 64)); err == nil {
		t.Fatal("changed control content was accepted")
	}
}

func githubAccepted(t *testing.T) v1.AcceptedRequestRecord {
	t.Helper()
	request := v1.Request{
		ProtocolVersion: v1.Version, RequestID: "req-1", SessionID: "session-1", Actor: "alice", Shell: v1.ShellPowerShell,
		Operation: v1.RequestOperationExecute, ProcessID: "",
		WorkingDirectory: `C:\Users\Alice\Projects`, Script: "Write-Output hello", TimeoutSeconds: 30,
		MaxOutputBytes: 4096, Artifacts: []v1.ArtifactSelection{},
	}
	digest, err := v1.DigestRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	return v1.AcceptedRequestRecord{
		ProtocolVersion: v1.Version, RequestID: request.RequestID, RequestDigest: digest, Request: request,
		Issue:            v1.IssueProvenance{Number: 1, NodeID: "I_example", SenderID: 2, SenderLogin: "alice"},
		Workflow:         v1.WorkflowProvenance{Repository: "alice/example-control", RunID: 3, RunAttempt: 1, EventName: "issues", EventAction: "opened", HeadSHA: strings.Repeat("1", 40)},
		ControlSourceSHA: strings.Repeat("2", 40), AcceptedAt: "2026-09-03T08:00:00Z",
	}
}
