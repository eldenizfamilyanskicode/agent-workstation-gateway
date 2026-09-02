package v1

func ValidateResultBinding(accepted AcceptedRequestRecord, result ResultRecord) error {
	if err := ValidateResultRecord(result); err != nil {
		return err
	}
	if err := ValidateExecutionReportBinding(accepted, executionReportFromResult(result)); err != nil {
		return err
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

func ValidateExecutionReportBinding(accepted AcceptedRequestRecord, report ExecutionReport) error {
	if err := ValidateAcceptedRequestRecord(accepted); err != nil {
		return err
	}
	if err := ValidateExecutionReport(report); err != nil {
		return err
	}
	if report.RequestID != accepted.RequestID {
		return validationError("request_id", "does-not-match-accepted-request")
	}
	if report.RequestDigest != accepted.RequestDigest {
		return validationError("request_digest", "does-not-match-accepted-request")
	}
	if report.Stdout.RetainedBytes > int64(accepted.Request.MaxOutputBytes) {
		return validationError("stdout.retained_bytes", "exceeds-accepted-output-limit")
	}
	if report.Stderr.RetainedBytes > int64(accepted.Request.MaxOutputBytes) {
		return validationError("stderr.retained_bytes", "exceeds-accepted-output-limit")
	}
	acceptedArtifactGroups := make(map[string]struct{}, len(accepted.Request.Artifacts))
	for _, selection := range accepted.Request.Artifacts {
		acceptedArtifactGroups[selection.Name] = struct{}{}
	}
	if len(acceptedArtifactGroups) == 0 && report.Artifacts.Status != ArtifactStatusNotRequested {
		return validationError("artifacts.status", "artifacts-not-requested")
	}
	if len(acceptedArtifactGroups) > 0 && report.Artifacts.Status == ArtifactStatusNotRequested {
		return validationError("artifacts.status", "requested-artifacts-not-represented")
	}
	for _, file := range report.Artifacts.Files {
		if _, acceptedGroup := acceptedArtifactGroups[file.Group]; !acceptedGroup {
			return validationError("artifacts.files.group", "not-in-accepted-request")
		}
	}
	for _, omission := range report.Artifacts.Omissions {
		if _, acceptedGroup := acceptedArtifactGroups[omission.Group]; !acceptedGroup {
			return validationError("artifacts.omissions.group", "not-in-accepted-request")
		}
	}
	return nil
}

func executionReportFromResult(result ResultRecord) ExecutionReport {
	return ExecutionReport{
		ProtocolVersion:      result.ProtocolVersion,
		RequestID:            result.RequestID,
		RequestDigest:        result.RequestDigest,
		AttemptID:            result.AttemptID,
		GatewaySourceSHA:     result.GatewaySourceSHA,
		CommandStatus:        result.CommandStatus,
		ExitCode:             result.ExitCode,
		StartedAt:            result.StartedAt,
		FinishedAt:           result.FinishedAt,
		DurationMilliseconds: result.DurationMilliseconds,
		Stdout:               result.Stdout,
		Stderr:               result.Stderr,
		Artifacts:            result.Artifacts,
	}
}
