package brokerwire

import (
	"encoding/json"
	"errors"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/strictjson"
)

var supportedFailures = map[Failure]struct{}{
	FailureNone:                 {},
	FailureInvalidFrame:         {},
	FailureInvalidEnvelope:      {},
	FailureAuthorizationDenied:  {},
	FailureExecutionUnavailable: {},
	FailureResponseUnavailable:  {},
}

func ValidatePreamble(preamble Preamble) error {
	if preamble.ProtocolVersion != CurrentVersion {
		return wireError("unsupported-version")
	}
	if _, supported := supportedFailures[preamble.Failure]; !supported {
		return wireError("unsupported-failure")
	}
	switch preamble.Outcome {
	case OutcomeExecution:
		if preamble.Failure != FailureNone {
			return wireError("execution-cannot-carry-failure")
		}
		if !lowerHexDigest(preamble.StdoutRetainedSHA256) || !lowerHexDigest(preamble.StderrRetainedSHA256) {
			return wireError("retained-digest-invalid")
		}
	case OutcomeRejected:
		if preamble.Failure == FailureNone {
			return wireError("rejection-requires-failure")
		}
		if preamble.StdoutRetainedSHA256 != "" || preamble.StderrRetainedSHA256 != "" {
			return wireError("rejection-cannot-carry-digests")
		}
	default:
		return wireError("unsupported-outcome")
	}
	return nil
}

func DecodePreamble(encoded []byte) (Preamble, error) {
	var preamble Preamble
	if err := strictjson.DecodeObject(encoded, MaxPreambleBytes, &preamble); err != nil {
		var decodeFailure *strictjson.Error
		if errors.As(err, &decodeFailure) {
			return Preamble{}, wireError("preamble-json-" + decodeFailure.Rule)
		}
		return Preamble{}, wireError("preamble-decode-failed")
	}
	if err := ValidatePreamble(preamble); err != nil {
		return Preamble{}, err
	}
	return preamble, nil
}

func MarshalCanonicalPreamble(preamble Preamble) ([]byte, error) {
	if err := ValidatePreamble(preamble); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(preamble)
	if err != nil || len(encoded) > MaxPreambleBytes {
		return nil, wireError("preamble-encode-failed")
	}
	return encoded, nil
}

func lowerHexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}
