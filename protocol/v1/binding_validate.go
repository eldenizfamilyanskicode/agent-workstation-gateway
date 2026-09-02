package v1

func ValidateResultBinding(accepted AcceptedRequestRecord, result ResultRecord) error {
	if err := ValidateAcceptedRequestRecord(accepted); err != nil {
		return err
	}
	if err := ValidateResultRecord(result); err != nil {
		return err
	}
	if result.RequestID != accepted.RequestID {
		return validationError("request_id", "does-not-match-accepted-request")
	}
	if result.RequestDigest != accepted.RequestDigest {
		return validationError("request_digest", "does-not-match-accepted-request")
	}
	if result.Stdout.TotalBytes > int64(accepted.Request.MaxOutputBytes) {
		return validationError("stdout.total_bytes", "exceeds-accepted-output-limit")
	}
	if result.Stderr.TotalBytes > int64(accepted.Request.MaxOutputBytes) {
		return validationError("stderr.total_bytes", "exceeds-accepted-output-limit")
	}
	acceptedArtifactGroups := make(map[string]struct{}, len(accepted.Request.Artifacts))
	for _, selection := range accepted.Request.Artifacts {
		acceptedArtifactGroups[selection.Name] = struct{}{}
	}
	if len(acceptedArtifactGroups) == 0 && result.Artifacts.Status != ArtifactStatusNotRequested {
		return validationError("artifacts.status", "artifacts-not-requested")
	}
	if len(acceptedArtifactGroups) > 0 && result.Artifacts.Status == ArtifactStatusNotRequested {
		return validationError("artifacts.status", "requested-artifacts-not-represented")
	}
	for _, file := range result.Artifacts.Files {
		if _, acceptedGroup := acceptedArtifactGroups[file.Group]; !acceptedGroup {
			return validationError("artifacts.files.group", "not-in-accepted-request")
		}
	}
	for _, omission := range result.Artifacts.Omissions {
		if _, acceptedGroup := acceptedArtifactGroups[omission.Group]; !acceptedGroup {
			return validationError("artifacts.omissions.group", "not-in-accepted-request")
		}
	}
	if result.Workflow.Repository != accepted.Workflow.Repository ||
		result.Workflow.RunID != accepted.Workflow.RunID ||
		result.Workflow.EventName != accepted.Workflow.EventName ||
		result.Workflow.EventAction != accepted.Workflow.EventAction ||
		result.Workflow.HeadSHA != accepted.Workflow.HeadSHA {
		return validationError("workflow", "does-not-match-acceptance-run")
	}
	return nil
}
