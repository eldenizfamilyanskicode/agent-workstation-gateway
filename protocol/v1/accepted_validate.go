package v1

func ValidateAcceptedRequestRecord(record AcceptedRequestRecord) error {
	if record.ProtocolVersion != Version {
		return validationError("protocol_version", "unsupported-version")
	}
	if err := validateIdentifier("request_id", record.RequestID); err != nil {
		return err
	}
	if err := ValidateRequest(record.Request); err != nil {
		return err
	}
	if record.RequestID != record.Request.RequestID {
		return validationError("request_id", "does-not-match-request")
	}
	if err := validateLowerHex("request_digest", record.RequestDigest, 64); err != nil {
		return err
	}
	requestDigest, err := DigestRequest(record.Request)
	if err != nil {
		return err
	}
	if record.RequestDigest != requestDigest {
		return validationError("request_digest", "does-not-match-request")
	}
	if err := validateIssueProvenance(record.Issue); err != nil {
		return err
	}
	if err := validateWorkflowProvenance(record.Workflow); err != nil {
		return err
	}
	if err := validateLowerHex("control_source_sha", record.ControlSourceSHA, 40); err != nil {
		return err
	}
	if _, err := validateCanonicalUTCTimestamp("accepted_at", record.AcceptedAt); err != nil {
		return err
	}
	return nil
}
