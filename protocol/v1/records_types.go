package v1

type AcceptedRequestRecord struct {
	ProtocolVersion  ProtocolVersion    `json:"protocol_version"`
	RequestID        string             `json:"request_id"`
	RequestDigest    string             `json:"request_digest"`
	Request          Request            `json:"request"`
	Issue            IssueProvenance    `json:"issue"`
	Workflow         WorkflowProvenance `json:"workflow"`
	ControlSourceSHA string             `json:"control_source_sha"`
	AcceptedAt       string             `json:"accepted_at"`
}

type IssueProvenance struct {
	Number      int64  `json:"number"`
	NodeID      string `json:"node_id"`
	SenderID    int64  `json:"sender_id"`
	SenderLogin string `json:"sender_login"`
}

type WorkflowProvenance struct {
	Repository  string `json:"repository"`
	RunID       int64  `json:"run_id"`
	RunAttempt  int    `json:"run_attempt"`
	EventName   string `json:"event_name"`
	EventAction string `json:"event_action"`
	HeadSHA     string `json:"head_sha"`
}

type CommandStatus string

const (
	CommandStatusCancelled     CommandStatus = "cancelled"
	CommandStatusCompleted     CommandStatus = "completed"
	CommandStatusFailed        CommandStatus = "failed"
	CommandStatusRuntimeFailed CommandStatus = "runtime_failed"
	CommandStatusTimedOut      CommandStatus = "timed_out"
)

type ArtifactStatus string

const (
	ArtifactStatusComplete              ArtifactStatus = "complete"
	ArtifactStatusCompleteWithOmissions ArtifactStatus = "complete_with_omissions"
	ArtifactStatusFailed                ArtifactStatus = "failed"
	ArtifactStatusNotRequested          ArtifactStatus = "not_requested"
)

type ArtifactOmissionReason string

const (
	ArtifactOmissionByteLimit        ArtifactOmissionReason = "byte_limit"
	ArtifactOmissionCollectionFailed ArtifactOmissionReason = "collection_failed"
	ArtifactOmissionFileLimit        ArtifactOmissionReason = "file_limit"
	ArtifactOmissionLinkRejected     ArtifactOmissionReason = "link_rejected"
	ArtifactOmissionNoMatch          ArtifactOmissionReason = "no_match"
	ArtifactOmissionPolicyRejected   ArtifactOmissionReason = "policy_rejected"
	ArtifactOmissionReadFailed       ArtifactOmissionReason = "read_failed"
	ArtifactOmissionUnsupportedType  ArtifactOmissionReason = "unsupported_type"
)

type ResultRecord struct {
	ProtocolVersion      ProtocolVersion    `json:"protocol_version"`
	RequestID            string             `json:"request_id"`
	RequestDigest        string             `json:"request_digest"`
	AttemptID            string             `json:"attempt_id"`
	GatewaySourceSHA     string             `json:"gateway_source_sha"`
	CommandStatus        CommandStatus      `json:"command_status"`
	ExitCode             *int64             `json:"exit_code"`
	StartedAt            string             `json:"started_at"`
	FinishedAt           string             `json:"finished_at"`
	DurationMilliseconds int64              `json:"duration_ms"`
	Stdout               OutputMetadata     `json:"stdout"`
	Stderr               OutputMetadata     `json:"stderr"`
	Artifacts            ArtifactManifest   `json:"artifacts"`
	FinalizedAt          string             `json:"finalized_at"`
	Workflow             WorkflowProvenance `json:"workflow"`
}

type OutputMetadata struct {
	SHA256        string `json:"sha256"`
	TotalBytes    int64  `json:"total_bytes"`
	RetainedBytes int64  `json:"retained_bytes"`
	Truncated     bool   `json:"truncated"`
}

type ArtifactManifest struct {
	Status    ArtifactStatus     `json:"status"`
	Files     []ArtifactFile     `json:"files"`
	Omissions []ArtifactOmission `json:"omissions"`
}

type ArtifactFile struct {
	Group     string `json:"group"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type ArtifactOmission struct {
	Group   string                 `json:"group"`
	Pattern string                 `json:"pattern"`
	Reason  ArtifactOmissionReason `json:"reason"`
}
