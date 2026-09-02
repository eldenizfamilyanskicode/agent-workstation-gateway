package v1

func FinalizeResultRecord(
	accepted AcceptedRequestRecord,
	report ExecutionReport,
	finalizedAt string,
	workflow WorkflowProvenance,
) (ResultRecord, error) {
	if err := ValidateExecutionReportBinding(accepted, report); err != nil {
		return ResultRecord{}, err
	}
	result := ResultRecord{
		ProtocolVersion:      report.ProtocolVersion,
		RequestID:            report.RequestID,
		RequestDigest:        report.RequestDigest,
		AttemptID:            report.AttemptID,
		GatewaySourceSHA:     report.GatewaySourceSHA,
		CommandStatus:        report.CommandStatus,
		ExitCode:             report.ExitCode,
		StartedAt:            report.StartedAt,
		FinishedAt:           report.FinishedAt,
		DurationMilliseconds: report.DurationMilliseconds,
		Stdout:               report.Stdout,
		Stderr:               report.Stderr,
		Artifacts:            report.Artifacts,
		FinalizedAt:          finalizedAt,
		Workflow:             workflow,
	}
	if err := ValidateResultBinding(accepted, result); err != nil {
		return ResultRecord{}, err
	}
	return result, nil
}
