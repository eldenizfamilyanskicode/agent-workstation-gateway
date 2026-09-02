package v1

import (
	"regexp"
	"strings"
	"time"
	"unicode"
)

var repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)
var senderLoginPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)

func validateIssueProvenance(issue IssueProvenance) error {
	if issue.Number <= 0 {
		return validationError("issue.number", "must-be-positive")
	}
	if issue.SenderID <= 0 {
		return validationError("issue.sender_id", "must-be-positive")
	}
	if len(issue.NodeID) == 0 || len(issue.NodeID) > 128 || strings.IndexFunc(issue.NodeID, unicode.IsSpace) >= 0 || containsControlCharacter(issue.NodeID) {
		return validationError("issue.node_id", "invalid-node-id")
	}
	if !senderLoginPattern.MatchString(issue.SenderLogin) {
		return validationError("issue.sender_login", "invalid-login")
	}
	return nil
}

func validateWorkflowProvenance(workflow WorkflowProvenance) error {
	if !repositoryPattern.MatchString(workflow.Repository) {
		return validationError("workflow.repository", "invalid-repository")
	}
	if workflow.RunID <= 0 {
		return validationError("workflow.run_id", "must-be-positive")
	}
	if workflow.RunAttempt <= 0 {
		return validationError("workflow.run_attempt", "must-be-positive")
	}
	if workflow.EventName != "issues" || workflow.EventAction != "opened" {
		return validationError("workflow.event", "unexpected-event")
	}
	return validateLowerHex("workflow.head_sha", workflow.HeadSHA, 40)
}

func validateLowerHex(field string, value string, expectedLength int) error {
	if len(value) != expectedLength {
		return validationError(field, "invalid-lower-hex")
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return validationError(field, "invalid-lower-hex")
		}
	}
	return nil
}

func validateCanonicalUTCTimestamp(field string, value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, validationError(field, "invalid-timestamp")
	}
	if parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, validationError(field, "not-canonical-utc")
	}
	return parsed, nil
}
