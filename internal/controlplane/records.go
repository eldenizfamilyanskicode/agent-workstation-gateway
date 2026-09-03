package controlplane

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/sourceversion"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

const MaxEventBytes = 256 * 1024

type WorkflowContext struct {
	Repository  string
	RunID       string
	RunAttempt  string
	EventName   string
	EventAction string
	HeadSHA     string
}

type issueEvent struct {
	Action string `json:"action"`
	Issue  struct {
		Number int64  `json:"number"`
		NodeID string `json:"node_id"`
		Body   string `json:"body"`
	} `json:"issue"`
	Sender struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
	} `json:"sender"`
}

type Error struct {
	Rule string
}

func (failure *Error) Error() string {
	return fmt.Sprintf("control plane operation failed: %s", failure.Rule)
}

func Accept(encodedEvent []byte, workflowContext WorkflowContext, controlSourceSHA string, acceptedAt time.Time) (v1.AcceptedRequestRecord, error) {
	workflow, err := workflowProvenance(workflowContext)
	if err != nil {
		return v1.AcceptedRequestRecord{}, err
	}
	if !sourceversion.IsCanonicalGitSHA(controlSourceSHA) {
		return v1.AcceptedRequestRecord{}, controlError("control-source-sha-invalid")
	}
	if len(encodedEvent) == 0 || len(encodedEvent) > MaxEventBytes {
		return v1.AcceptedRequestRecord{}, controlError("event-size-invalid")
	}
	var event issueEvent
	if err := json.Unmarshal(encodedEvent, &event); err != nil {
		return v1.AcceptedRequestRecord{}, controlError("event-invalid")
	}
	if event.Action != "opened" || event.Action != workflowContext.EventAction || event.Issue.Number <= 0 ||
		event.Issue.NodeID == "" || event.Sender.ID <= 0 || event.Sender.Login == "" {
		return v1.AcceptedRequestRecord{}, controlError("event-invalid")
	}
	request, err := v1.DecodeRequest([]byte(event.Issue.Body))
	if err != nil {
		return v1.AcceptedRequestRecord{}, controlError("request-invalid")
	}
	digest, err := v1.DigestRequest(request)
	if err != nil {
		return v1.AcceptedRequestRecord{}, controlError("request-invalid")
	}
	record := v1.AcceptedRequestRecord{
		ProtocolVersion: v1.Version,
		RequestID:       request.RequestID,
		RequestDigest:   digest,
		Request:         request,
		Issue: v1.IssueProvenance{
			Number: event.Issue.Number, NodeID: event.Issue.NodeID,
			SenderID: event.Sender.ID, SenderLogin: event.Sender.Login,
		},
		Workflow:         workflow,
		ControlSourceSHA: controlSourceSHA,
		AcceptedAt:       canonicalTime(acceptedAt),
	}
	if err := v1.ValidateAcceptedRequestRecord(record); err != nil {
		return v1.AcceptedRequestRecord{}, controlError("accepted-record-invalid")
	}
	return record, nil
}

func Finalize(accepted v1.AcceptedRequestRecord, report v1.ExecutionReport, workflowContext WorkflowContext, finalizedAt time.Time) (v1.ResultRecord, error) {
	workflow, err := workflowProvenance(workflowContext)
	if err != nil {
		return v1.ResultRecord{}, err
	}
	result, err := v1.FinalizeResultRecord(accepted, report, canonicalTime(finalizedAt), workflow)
	if err != nil {
		return v1.ResultRecord{}, controlError("result-binding-invalid")
	}
	return result, nil
}

func workflowProvenance(context WorkflowContext) (v1.WorkflowProvenance, error) {
	runID, err := strconv.ParseInt(context.RunID, 10, 64)
	if err != nil || runID <= 0 {
		return v1.WorkflowProvenance{}, controlError("workflow-context-invalid")
	}
	runAttempt, err := strconv.Atoi(context.RunAttempt)
	if err != nil || runAttempt <= 0 {
		return v1.WorkflowProvenance{}, controlError("workflow-context-invalid")
	}
	workflow := v1.WorkflowProvenance{
		Repository: context.Repository, RunID: runID, RunAttempt: runAttempt,
		EventName: context.EventName, EventAction: context.EventAction, HeadSHA: context.HeadSHA,
	}
	return workflow, nil
}

func canonicalTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func controlError(rule string) error { return &Error{Rule: rule} }
