package v1

func DecodeAcceptedRequestRecord(encodedRecord []byte) (AcceptedRequestRecord, error) {
	var record AcceptedRequestRecord
	if err := decodeStrictObject(encodedRecord, MaxAcceptedRecordBytes, "accepted_request", &record); err != nil {
		return AcceptedRequestRecord{}, err
	}
	if err := ValidateAcceptedRequestRecord(record); err != nil {
		return AcceptedRequestRecord{}, err
	}
	return record, nil
}

func MarshalCanonicalAcceptedRequestRecord(record AcceptedRequestRecord) ([]byte, error) {
	if err := ValidateAcceptedRequestRecord(record); err != nil {
		return nil, err
	}
	return marshalCanonicalRecord(record, MaxAcceptedRecordBytes, "accepted_request")
}

func DigestAcceptedRequestRecord(record AcceptedRequestRecord) (string, error) {
	encodedRecord, err := MarshalCanonicalAcceptedRequestRecord(record)
	if err != nil {
		return "", err
	}
	return digestCanonicalBytes(encodedRecord), nil
}

func DecodeExecutionReport(encodedReport []byte) (ExecutionReport, error) {
	var report ExecutionReport
	if err := decodeStrictObject(encodedReport, MaxExecutionReportBytes, "execution_report", &report); err != nil {
		return ExecutionReport{}, err
	}
	if err := ValidateExecutionReport(report); err != nil {
		return ExecutionReport{}, err
	}
	return report, nil
}

func MarshalCanonicalExecutionReport(report ExecutionReport) ([]byte, error) {
	if err := ValidateExecutionReport(report); err != nil {
		return nil, err
	}
	return marshalCanonicalRecord(report, MaxExecutionReportBytes, "execution_report")
}

func DigestExecutionReport(report ExecutionReport) (string, error) {
	encodedReport, err := MarshalCanonicalExecutionReport(report)
	if err != nil {
		return "", err
	}
	return digestCanonicalBytes(encodedReport), nil
}

func DecodeResultRecord(encodedRecord []byte) (ResultRecord, error) {
	var record ResultRecord
	if err := decodeStrictObject(encodedRecord, MaxResultRecordBytes, "result", &record); err != nil {
		return ResultRecord{}, err
	}
	if err := ValidateResultRecord(record); err != nil {
		return ResultRecord{}, err
	}
	return record, nil
}

func MarshalCanonicalResultRecord(record ResultRecord) ([]byte, error) {
	if err := ValidateResultRecord(record); err != nil {
		return nil, err
	}
	return marshalCanonicalRecord(record, MaxResultRecordBytes, "result")
}

func DigestResultRecord(record ResultRecord) (string, error) {
	encodedRecord, err := MarshalCanonicalResultRecord(record)
	if err != nil {
		return "", err
	}
	return digestCanonicalBytes(encodedRecord), nil
}
