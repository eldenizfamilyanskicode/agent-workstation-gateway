package githubcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/runnerregistration"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

const (
	apiBaseURL       = "https://api.github.com"
	apiVersion       = "2022-11-28"
	maxTokenBytes    = 4096
	maxResponseBytes = 64 * 1024
)

type Client struct {
	baseURL    string
	repository runnerregistration.PrivateRepository
	token      []byte
	http       *http.Client
}

type repositoryResponse struct {
	FullName   string `json:"full_name"`
	Private    bool   `json:"private"`
	Visibility string `json:"visibility"`
	Owner      struct {
		Login string `json:"login"`
	} `json:"owner"`
}

type userResponse struct {
	Login string `json:"login"`
}

type collaboratorResponse struct {
	Login string `json:"login"`
}

type contentResponse struct {
	Type     string `json:"type"`
	Encoding string `json:"encoding"`
	Content  string `json:"content"`
	SHA      string `json:"sha"`
}

type runnerTokenResponse struct {
	Token string `json:"token"`
}

type runnersResponse struct {
	TotalCount int `json:"total_count"`
	Runners    []struct {
		ID     int64  `json:"id"`
		Name   string `json:"name"`
		Labels []struct {
			Name string `json:"name"`
		} `json:"labels"`
	} `json:"runners"`
}

type createFileRequest struct {
	Message string `json:"message"`
	Content string `json:"content"`
}

type Error struct {
	Rule string
}

func (failure *Error) Error() string {
	return fmt.Sprintf("GitHub control operation failed: %s", failure.Rule)
}

func New(token []byte, repository string) (*Client, error) {
	return newClient(apiBaseURL, token, repository, &http.Client{Timeout: 30 * time.Second}, false)
}

func newClient(baseURL string, token []byte, repository string, httpClient *http.Client, allowHTTP bool) (*Client, error) {
	verified, err := runnerregistration.VerifyPrivateRepository(repository, true)
	if err != nil || !validToken(token) || httpClient == nil {
		return nil, githubError("client-input-invalid")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Host == "" ||
		(parsed.Scheme != "https" && !(allowHTTP && parsed.Scheme == "http")) {
		return nil, githubError("api-url-invalid")
	}
	return &Client{
		baseURL: strings.TrimSuffix(baseURL, "/"), repository: verified,
		token: append([]byte(nil), token...), http: httpClient,
	}, nil
}

func (client *Client) Close() {
	if client == nil {
		return
	}
	zeroBytes(client.token)
	client.token = nil
}

func (client *Client) VerifyPrivate(ctx context.Context) error {
	repository, err := client.readRepository(ctx)
	if err != nil {
		return err
	}
	if repository.FullName != client.repository.Name() || !repository.Private || repository.Visibility != "private" {
		return githubError("private-repository-required")
	}
	return nil
}

// VerifyExclusivePrivate is the deliberately small v0.1 requester boundary:
// one personal private repository whose only effective collaborator is its
// authenticated owner. Organization/inherited readership requires a later
// explicit reader policy instead of being silently accepted.
func (client *Client) VerifyExclusivePrivate(ctx context.Context) error {
	repository, err := client.readRepository(ctx)
	if err != nil {
		return err
	}
	if repository.FullName != client.repository.Name() || !repository.Private || repository.Visibility != "private" {
		return githubError("private-repository-required")
	}
	user, err := client.readUser(ctx)
	if err != nil || repository.Owner.Login == "" || user.Login == "" ||
		!strings.EqualFold(repository.Owner.Login, user.Login) {
		return githubError("exclusive-personal-repository-required")
	}
	response, err := client.request(ctx, http.MethodGet, "/repos/"+client.repository.Name()+"/collaborators?affiliation=all&per_page=100", nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || strings.Contains(response.Header.Get("Link"), `rel="next"`) {
		return githubError("repository-readers-unavailable")
	}
	encoded, err := readResponse(response.Body)
	if err != nil {
		return githubError("repository-readers-invalid")
	}
	var collaborators []collaboratorResponse
	if err := json.Unmarshal(encoded, &collaborators); err != nil {
		return githubError("repository-readers-invalid")
	}
	for _, collaborator := range collaborators {
		if collaborator.Login == "" || !strings.EqualFold(collaborator.Login, user.Login) {
			return githubError("unexpected-repository-reader")
		}
	}
	return nil
}

func (client *Client) CreatePersonalPrivate(ctx context.Context) error {
	user, err := client.readUser(ctx)
	if err != nil {
		return err
	}
	parts := strings.Split(client.repository.Name(), "/")
	if len(parts) != 2 || !strings.EqualFold(parts[0], user.Login) {
		return githubError("personal-repository-owner-mismatch")
	}
	payload, err := json.Marshal(struct {
		Name        string `json:"name"`
		Private     bool   `json:"private"`
		HasIssues   bool   `json:"has_issues"`
		HasProjects bool   `json:"has_projects"`
		HasWiki     bool   `json:"has_wiki"`
		AutoInit    bool   `json:"auto_init"`
	}{Name: parts[1], Private: true, HasIssues: true, AutoInit: true})
	if err != nil {
		return githubError("repository-create-invalid")
	}
	response, err := client.request(ctx, http.MethodPost, "/user/repos", payload)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return githubError("repository-create-failed")
	}
	encoded, err := readResponse(response.Body)
	if err != nil {
		return githubError("repository-create-response-invalid")
	}
	var repository repositoryResponse
	if err := json.Unmarshal(encoded, &repository); err != nil || repository.FullName != client.repository.Name() ||
		!repository.Private || repository.Visibility != "private" {
		return githubError("private-repository-required")
	}
	return nil
}

func (client *Client) EnsureControlFile(ctx context.Context, path string, content []byte) (bool, error) {
	if path != ".github/workflows/execute-request.yml" && path != "control-version.json" {
		return false, githubError("control-file-path-denied")
	}
	if len(content) == 0 || len(content) > 256*1024 {
		return false, githubError("control-file-content-invalid")
	}
	if err := client.VerifyExclusivePrivate(ctx); err != nil {
		return false, err
	}
	apiPath := "/repos/" + client.repository.Name() + "/contents/" + path
	response, err := client.request(ctx, http.MethodGet, apiPath, nil)
	if err != nil {
		return false, err
	}
	if response.StatusCode == http.StatusOK {
		defer response.Body.Close()
		encoded, readErr := readResponse(response.Body)
		if readErr != nil {
			return false, githubError("control-file-response-invalid")
		}
		var existing contentResponse
		if json.Unmarshal(encoded, &existing) != nil || existing.Type != "file" || existing.Encoding != "base64" || existing.SHA == "" {
			return false, githubError("control-file-response-invalid")
		}
		existingContent, decodeErr := base64.StdEncoding.DecodeString(strings.ReplaceAll(existing.Content, "\n", ""))
		if decodeErr != nil || !bytes.Equal(existingContent, content) {
			return false, githubError("control-file-conflict")
		}
		return false, nil
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		return false, githubError("control-file-read-failed")
	}
	payload, err := json.Marshal(createFileRequest{
		Message: "Install Agent Workstation Gateway control file",
		Content: base64.StdEncoding.EncodeToString(content),
	})
	if err != nil {
		return false, githubError("control-file-encode-failed")
	}
	created, err := client.request(ctx, http.MethodPut, apiPath, payload)
	if err != nil {
		return false, err
	}
	defer created.Body.Close()
	if created.StatusCode != http.StatusCreated {
		return false, githubError("control-file-create-failed")
	}
	return true, nil
}

func (client *Client) RegistrationToken(ctx context.Context) ([]byte, error) {
	return client.runnerToken(ctx, "registration-token")
}

func (client *Client) RemovalToken(ctx context.Context) ([]byte, error) {
	return client.runnerToken(ctx, "remove-token")
}

func (client *Client) DeleteOwnedControlFile(ctx context.Context, path string, expectedSHA256 string) error {
	if err := client.VerifyOwnedControlFile(ctx, path, expectedSHA256); err != nil {
		return err
	}
	apiPath := "/repos/" + client.repository.Name() + "/contents/" + path
	existing, content, err := client.readContent(ctx, apiPath)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != expectedSHA256 {
		return githubError("control-file-delete-conflict")
	}
	payload, err := json.Marshal(struct {
		Message string `json:"message"`
		SHA     string `json:"sha"`
	}{Message: "Uninstall Agent Workstation Gateway control file", SHA: existing.SHA})
	if err != nil {
		return githubError("control-file-delete-encode-failed")
	}
	response, err := client.request(ctx, http.MethodDelete, apiPath, payload)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return githubError("control-file-delete-failed")
	}
	return nil
}

func (client *Client) VerifyOwnedControlFile(ctx context.Context, path string, expectedSHA256 string) error {
	if (path != ".github/workflows/execute-request.yml" && path != "control-version.json") ||
		len(expectedSHA256) != 64 {
		return githubError("control-file-delete-input-invalid")
	}
	if err := client.VerifyExclusivePrivate(ctx); err != nil {
		return err
	}
	apiPath := "/repos/" + client.repository.Name() + "/contents/" + path
	_, content, err := client.readContent(ctx, apiPath)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != expectedSHA256 {
		return githubError("control-file-delete-conflict")
	}
	return nil
}

func (client *Client) DeleteRunner(ctx context.Context, runnerName string) error {
	runnerID, err := client.verifyRunner(ctx, runnerName)
	if err != nil {
		return err
	}
	deleted, err := client.request(ctx, http.MethodDelete, "/repos/"+client.repository.Name()+"/actions/runners/"+strconv.FormatInt(runnerID, 10), nil)
	if err != nil {
		return err
	}
	defer deleted.Body.Close()
	if deleted.StatusCode != http.StatusNoContent {
		return githubError("runner-delete-failed")
	}
	return nil
}

func (client *Client) VerifyRunner(ctx context.Context, runnerName string) error {
	_, err := client.verifyRunner(ctx, runnerName)
	return err
}

func (client *Client) verifyRunner(ctx context.Context, runnerName string) (int64, error) {
	if len(runnerName) == 0 || len(runnerName) > 64 {
		return 0, githubError("runner-name-invalid")
	}
	if err := client.VerifyExclusivePrivate(ctx); err != nil {
		return 0, err
	}
	response, err := client.request(ctx, http.MethodGet, "/repos/"+client.repository.Name()+"/actions/runners?per_page=100", nil)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || strings.Contains(response.Header.Get("Link"), `rel="next"`) {
		return 0, githubError("runner-list-failed")
	}
	encoded, err := readResponse(response.Body)
	if err != nil {
		return 0, githubError("runner-list-response-invalid")
	}
	var runners runnersResponse
	if json.Unmarshal(encoded, &runners) != nil || runners.TotalCount != len(runners.Runners) {
		return 0, githubError("runner-list-response-invalid")
	}
	var runnerID int64
	for _, runner := range runners.Runners {
		if runner.Name != runnerName {
			continue
		}
		if runnerID != 0 || runner.ID <= 0 || !hasGatewayLabel(runner.Labels) {
			return 0, githubError("runner-identity-conflict")
		}
		runnerID = runner.ID
	}
	if runnerID == 0 {
		return 0, githubError("runner-not-found")
	}
	return runnerID, nil
}

func hasGatewayLabel(labels []struct {
	Name string `json:"name"`
}) bool {
	for _, label := range labels {
		if label.Name == runnerregistration.RegistrationLabel {
			return true
		}
	}
	return false
}

func (client *Client) readRepository(ctx context.Context) (repositoryResponse, error) {
	if client == nil || ctx == nil || len(client.token) == 0 {
		return repositoryResponse{}, githubError("client-closed")
	}
	response, err := client.request(ctx, http.MethodGet, "/repos/"+client.repository.Name(), nil)
	if err != nil {
		return repositoryResponse{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return repositoryResponse{}, githubError("repository-read-failed")
	}
	encoded, err := readResponse(response.Body)
	if err != nil {
		return repositoryResponse{}, githubError("repository-response-invalid")
	}
	var repository repositoryResponse
	if err := json.Unmarshal(encoded, &repository); err != nil {
		return repositoryResponse{}, githubError("repository-response-invalid")
	}
	return repository, nil
}

func (client *Client) readUser(ctx context.Context) (userResponse, error) {
	response, err := client.request(ctx, http.MethodGet, "/user", nil)
	if err != nil {
		return userResponse{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return userResponse{}, githubError("authenticated-user-read-failed")
	}
	encoded, err := readResponse(response.Body)
	if err != nil {
		return userResponse{}, githubError("authenticated-user-response-invalid")
	}
	var user userResponse
	if json.Unmarshal(encoded, &user) != nil || user.Login == "" {
		return userResponse{}, githubError("authenticated-user-response-invalid")
	}
	return user, nil
}

func (client *Client) runnerToken(ctx context.Context, kind string) ([]byte, error) {
	if kind != "registration-token" && kind != "remove-token" {
		return nil, githubError("runner-token-kind-invalid")
	}
	if err := client.VerifyExclusivePrivate(ctx); err != nil {
		return nil, err
	}
	response, err := client.request(ctx, http.MethodPost, "/repos/"+client.repository.Name()+"/actions/runners/"+kind, []byte("{}"))
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return nil, githubError("runner-token-request-failed")
	}
	encoded, err := readResponse(response.Body)
	if err != nil {
		return nil, githubError("runner-token-response-invalid")
	}
	var result runnerTokenResponse
	if json.Unmarshal(encoded, &result) != nil || !validToken([]byte(result.Token)) {
		return nil, githubError("runner-token-response-invalid")
	}
	return []byte(result.Token), nil
}

func readResponse(reader io.Reader) ([]byte, error) {
	encoded, err := io.ReadAll(io.LimitReader(reader, maxResponseBytes+1))
	if err != nil || len(encoded) > maxResponseBytes {
		return nil, githubError("response-size-invalid")
	}
	return encoded, nil
}

func (client *Client) readContent(ctx context.Context, apiPath string) (contentResponse, []byte, error) {
	response, err := client.request(ctx, http.MethodGet, apiPath, nil)
	if err != nil {
		return contentResponse{}, nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return contentResponse{}, nil, githubError("control-file-read-failed")
	}
	encoded, err := readResponse(response.Body)
	if err != nil {
		return contentResponse{}, nil, githubError("control-file-response-invalid")
	}
	var existing contentResponse
	if json.Unmarshal(encoded, &existing) != nil || existing.Type != "file" || existing.Encoding != "base64" || existing.SHA == "" {
		return contentResponse{}, nil, githubError("control-file-response-invalid")
	}
	content, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(existing.Content, "\n", ""))
	if err != nil {
		return contentResponse{}, nil, githubError("control-file-response-invalid")
	}
	return existing, content, nil
}

func (client *Client) PublishAccepted(ctx context.Context, record v1.AcceptedRequestRecord) error {
	if err := v1.ValidateAcceptedRequestRecord(record); err != nil || record.Workflow.Repository != client.repository.Name() {
		return githubError("accepted-record-invalid")
	}
	encoded, err := v1.MarshalCanonicalAcceptedRequestRecord(record)
	if err != nil {
		return githubError("accepted-record-invalid")
	}
	return client.create(ctx, record.RequestID, "accepted.json", encoded)
}

func (client *Client) PublishResult(ctx context.Context, record v1.ResultRecord) error {
	if err := v1.ValidateResultRecord(record); err != nil || record.Workflow.Repository != client.repository.Name() {
		return githubError("result-record-invalid")
	}
	encoded, err := v1.MarshalCanonicalResultRecord(record)
	if err != nil {
		return githubError("result-record-invalid")
	}
	return client.create(ctx, record.RequestID, "result.json", encoded)
}

func (client *Client) create(ctx context.Context, requestID string, name string, encoded []byte) error {
	if err := client.VerifyPrivate(ctx); err != nil {
		return err
	}
	payload, err := json.Marshal(createFileRequest{
		Message: "Record AWG " + name + " for " + requestID,
		Content: base64.StdEncoding.EncodeToString(encoded),
	})
	if err != nil {
		return githubError("publication-encode-failed")
	}
	path := "/repos/" + client.repository.Name() + "/contents/ledger/requests/" + url.PathEscape(requestID) + "/" + name
	response, err := client.request(ctx, http.MethodPut, path, payload)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnprocessableEntity || response.StatusCode == http.StatusConflict {
		return githubError("create-once-conflict")
	}
	if response.StatusCode != http.StatusCreated {
		return githubError("publication-failed")
	}
	return nil
}

func (client *Client) request(ctx context.Context, method string, path string, body []byte) (*http.Response, error) {
	if client == nil || client.http == nil || len(client.token) == 0 {
		return nil, githubError("client-closed")
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, client.baseURL+path, reader)
	if err != nil {
		return nil, githubError("request-create-failed")
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+string(client.token))
	request.Header.Set("X-GitHub-Api-Version", apiVersion)
	request.Header.Set("User-Agent", "agent-workstation-gateway/v0.1")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}
	response, err := client.http.Do(request)
	if err != nil {
		return nil, githubError("request-failed")
	}
	return response, nil
}

func validToken(token []byte) bool {
	if len(token) < 16 || len(token) > maxTokenBytes {
		return false
	}
	for _, value := range token {
		if value < 0x21 || value > 0x7e {
			return false
		}
	}
	return true
}

//go:noinline
func zeroBytes(buffer []byte) {
	for index := range buffer {
		buffer[index] = 0
	}
	runtime.KeepAlive(buffer)
}

func githubError(rule string) error { return &Error{Rule: rule} }
