package brokerproto

import v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"

type Version uint8

const CurrentVersion Version = 1

type Operation string

const OperationExecute Operation = "execute"

type ExecuteEnvelope struct {
	ProtocolVersion Version                  `json:"protocol_version"`
	Operation       Operation                `json:"operation"`
	AttemptID       string                   `json:"attempt_id"`
	AcceptedRequest v1.AcceptedRequestRecord `json:"accepted_request"`
}
