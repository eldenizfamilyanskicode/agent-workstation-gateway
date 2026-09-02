package brokerproto

import (
	"encoding/json"
	"errors"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/strictjson"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

const MaxExecuteEnvelopeBytes = v1.MaxAcceptedRecordBytes + 16*1024

func DecodeExecuteEnvelope(encoded []byte) (ExecuteEnvelope, error) {
	var envelope ExecuteEnvelope
	if err := strictjson.DecodeObject(encoded, MaxExecuteEnvelopeBytes, &envelope); err != nil {
		var decodeFailure *strictjson.Error
		if errors.As(err, &decodeFailure) {
			return ExecuteEnvelope{}, protocolError("envelope", "json-"+decodeFailure.Rule)
		}
		return ExecuteEnvelope{}, protocolError("envelope", "json-decode")
	}
	if err := ValidateExecuteEnvelope(envelope); err != nil {
		return ExecuteEnvelope{}, err
	}
	return envelope, nil
}

func MarshalCanonicalExecuteEnvelope(envelope ExecuteEnvelope) ([]byte, error) {
	if err := ValidateExecuteEnvelope(envelope); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, protocolError("envelope", "canonical-encode")
	}
	if len(encoded) > MaxExecuteEnvelopeBytes {
		return nil, protocolError("envelope", "canonical-size-limit")
	}
	return encoded, nil
}
