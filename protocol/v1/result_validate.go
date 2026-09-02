package v1

var supportedCommandStatuses = map[CommandStatus]struct{}{
	CommandStatusCancelled:     {},
	CommandStatusCompleted:     {},
	CommandStatusFailed:        {},
	CommandStatusRuntimeFailed: {},
	CommandStatusTimedOut:      {},
}

var supportedArtifactStatuses = map[ArtifactStatus]struct{}{
	ArtifactStatusComplete:              {},
	ArtifactStatusCompleteWithOmissions: {},
	ArtifactStatusFailed:                {},
	ArtifactStatusNotRequested:          {},
}

var supportedArtifactOmissionReasons = map[ArtifactOmissionReason]struct{}{
	ArtifactOmissionByteLimit:        {},
	ArtifactOmissionCollectionFailed: {},
	ArtifactOmissionFileLimit:        {},
	ArtifactOmissionLinkRejected:     {},
	ArtifactOmissionNoMatch:          {},
	ArtifactOmissionPolicyRejected:   {},
	ArtifactOmissionReadFailed:       {},
	ArtifactOmissionUnsupportedType:  {},
}

func ValidateResultRecord(record ResultRecord) error {
	if err := ValidateExecutionReport(executionReportFromResult(record)); err != nil {
		return err
	}
	finishedAt, err := validateCanonicalUTCTimestamp("finished_at", record.FinishedAt)
	if err != nil {
		return err
	}
	finalizedAt, err := validateCanonicalUTCTimestamp("finalized_at", record.FinalizedAt)
	if err != nil {
		return err
	}
	if finalizedAt.Before(finishedAt) {
		return validationError("finalized_at", "before-finished-at")
	}
	return validateWorkflowProvenance(record.Workflow)
}

func ValidateExecutionReport(report ExecutionReport) error {
	if report.ProtocolVersion != Version {
		return validationError("protocol_version", "unsupported-version")
	}
	if err := validateIdentifier("request_id", report.RequestID); err != nil {
		return err
	}
	if err := validateLowerHex("request_digest", report.RequestDigest, 64); err != nil {
		return err
	}
	if err := validateIdentifier("attempt_id", report.AttemptID); err != nil {
		return err
	}
	if err := validateLowerHex("gateway_source_sha", report.GatewaySourceSHA, 40); err != nil {
		return err
	}
	if err := validateCommandOutcome(report.CommandStatus, report.ExitCode); err != nil {
		return err
	}
	startedAt, err := validateCanonicalUTCTimestamp("started_at", report.StartedAt)
	if err != nil {
		return err
	}
	finishedAt, err := validateCanonicalUTCTimestamp("finished_at", report.FinishedAt)
	if err != nil {
		return err
	}
	if finishedAt.Before(startedAt) {
		return validationError("finished_at", "before-started-at")
	}
	if report.DurationMilliseconds != finishedAt.Sub(startedAt).Milliseconds() {
		return validationError("duration_ms", "does-not-match-timestamps")
	}
	if err := validateOutputMetadata("stdout", report.Stdout); err != nil {
		return err
	}
	if err := validateOutputMetadata("stderr", report.Stderr); err != nil {
		return err
	}
	if err := validateArtifactManifest(report.Artifacts); err != nil {
		return err
	}
	return nil
}

func validateCommandOutcome(status CommandStatus, exitCode *int64) error {
	if _, supported := supportedCommandStatuses[status]; !supported {
		return validationError("command_status", "unsupported-status")
	}
	switch status {
	case CommandStatusCompleted:
		if exitCode == nil || *exitCode != 0 {
			return validationError("exit_code", "completed-requires-zero")
		}
	case CommandStatusFailed:
		if exitCode == nil || *exitCode <= 0 || *exitCode > 4294967295 {
			return validationError("exit_code", "failed-requires-platform-code")
		}
	case CommandStatusCancelled, CommandStatusRuntimeFailed, CommandStatusTimedOut:
		if exitCode != nil {
			return validationError("exit_code", "status-requires-null")
		}
	}
	return nil
}

func validateOutputMetadata(field string, output OutputMetadata) error {
	if err := validateLowerHex(field+".sha256", output.SHA256, 64); err != nil {
		return err
	}
	if output.TotalBytes < 0 {
		return validationError(field+".total_bytes", "negative")
	}
	if output.RetainedBytes < 0 || output.RetainedBytes > MaxOutputBytes || output.RetainedBytes > output.TotalBytes {
		return validationError(field+".retained_bytes", "outside-total-bytes")
	}
	if output.Truncated && output.RetainedBytes >= output.TotalBytes {
		return validationError(field+".truncated", "requires-omitted-bytes")
	}
	if !output.Truncated && output.RetainedBytes != output.TotalBytes {
		return validationError(field+".truncated", "false-requires-all-bytes")
	}
	return nil
}

func validateArtifactManifest(manifest ArtifactManifest) error {
	if _, supported := supportedArtifactStatuses[manifest.Status]; !supported {
		return validationError("artifacts.status", "unsupported-status")
	}
	if manifest.Files == nil || manifest.Omissions == nil {
		return validationError("artifacts", "arrays-required")
	}
	if len(manifest.Files) > MaxArtifactFiles {
		return validationError("artifacts.files", "too-many-files")
	}
	if len(manifest.Omissions) > MaxArtifactOmissions {
		return validationError("artifacts.omissions", "too-many-omissions")
	}
	if err := validateArtifactStatusShape(manifest); err != nil {
		return err
	}

	seenFiles := make(map[string]struct{}, len(manifest.Files))
	var totalBytes int64
	for _, file := range manifest.Files {
		if err := validateArtifactGroup("artifacts.files.group", file.Group); err != nil {
			return err
		}
		if err := validateArtifactFilePath(file.Path); err != nil {
			return err
		}
		if err := validateLowerHex("artifacts.files.sha256", file.SHA256, 64); err != nil {
			return err
		}
		if file.SizeBytes < 0 || file.SizeBytes > MaxArtifactFileBytes {
			return validationError("artifacts.files.size_bytes", "outside-allowed-range")
		}
		fileIdentity := file.Group + "\x00" + file.Path
		if _, exists := seenFiles[fileIdentity]; exists {
			return validationError("artifacts.files", "duplicate-file")
		}
		seenFiles[fileIdentity] = struct{}{}
		totalBytes += file.SizeBytes
		if totalBytes > MaxTotalArtifactBytes {
			return validationError("artifacts.files", "total-bytes-exceeded")
		}
	}

	seenOmissions := make(map[string]struct{}, len(manifest.Omissions))
	for _, omission := range manifest.Omissions {
		if err := validateArtifactGroup("artifacts.omissions.group", omission.Group); err != nil {
			return err
		}
		if err := validateArtifactOmissionPattern(omission.Pattern); err != nil {
			return err
		}
		if _, supported := supportedArtifactOmissionReasons[omission.Reason]; !supported {
			return validationError("artifacts.omissions.reason", "unsupported-reason")
		}
		omissionIdentity := omission.Group + "\x00" + omission.Pattern + "\x00" + string(omission.Reason)
		if _, exists := seenOmissions[omissionIdentity]; exists {
			return validationError("artifacts.omissions", "duplicate-omission")
		}
		seenOmissions[omissionIdentity] = struct{}{}
	}
	return nil
}

func validateArtifactStatusShape(manifest ArtifactManifest) error {
	switch manifest.Status {
	case ArtifactStatusNotRequested:
		if len(manifest.Files) != 0 || len(manifest.Omissions) != 0 {
			return validationError("artifacts.status", "not-requested-requires-empty")
		}
	case ArtifactStatusComplete:
		if len(manifest.Files) == 0 || len(manifest.Omissions) != 0 {
			return validationError("artifacts.status", "complete-requires-files-only")
		}
	case ArtifactStatusCompleteWithOmissions, ArtifactStatusFailed:
		if len(manifest.Omissions) == 0 {
			return validationError("artifacts.status", "status-requires-omissions")
		}
	}
	return nil
}

func validateArtifactGroup(field string, group string) error {
	if len(group) == 0 || len(group) > MaxArtifactGroupBytes || !identifierPattern.MatchString(group) {
		return validationError(field, "invalid-identifier")
	}
	return nil
}
