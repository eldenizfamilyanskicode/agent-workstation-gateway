package githubcontrol

import (
	"bytes"
	"context"
	"encoding/base64"
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
	if client == nil || ctx == nil || len(client.token) == 0 {
		return githubError("client-closed")
	}
	response, err := client.request(ctx, http.MethodGet, "/repos/"+client.repository.Name(), nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return githubError("repository-read-failed")
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(encoded) > maxResponseBytes {
		return githubError("repository-response-invalid")
	}
	var repository repositoryResponse
	if err := json.Unmarshal(encoded, &repository); err != nil || repository.FullName != client.repository.Name() ||
		!repository.Private || repository.Visibility != "private" {
		return githubError("private-repository-required")
	}
	return nil
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
