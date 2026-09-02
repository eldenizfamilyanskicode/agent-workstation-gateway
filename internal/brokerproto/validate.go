package brokerproto

import (
	"regexp"

	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

var attemptIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

func ValidateExecuteEnvelope(envelope ExecuteEnvelope) error {
	if envelope.ProtocolVersion != CurrentVersion {
		return protocolError("protocol_version", "unsupported-version")
	}
	if envelope.Operation != OperationExecute {
		return protocolError("operation", "unsupported-operation")
	}
	if !attemptIDPattern.MatchString(envelope.AttemptID) {
		return protocolError("attempt_id", "invalid-identifier")
	}
	if err := v1.ValidateAcceptedRequestRecord(envelope.AcceptedRequest); err != nil {
		return protocolError("accepted_request", "invalid-accepted-record")
	}
	return nil
}
