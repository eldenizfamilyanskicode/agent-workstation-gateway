package v1

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func MarshalCanonicalRequest(request Request) ([]byte, error) {
	if err := ValidateRequest(request); err != nil {
		return nil, err
	}
	return marshalCanonicalRecord(request, MaxRequestBytes, "request")
}

func marshalCanonicalRecord(record any, maximumBytes int, field string) ([]byte, error) {
	encodedRecord, err := json.Marshal(record)
	if err != nil {
		return nil, decodeError(field, "canonical-encode")
	}
	if len(encodedRecord) > maximumBytes {
		return nil, validationError(field, "canonical-size-limit")
	}
	return encodedRecord, nil
}

func DigestRequest(request Request) (string, error) {
	encodedRequest, err := MarshalCanonicalRequest(request)
	if err != nil {
		return "", err
	}
	return digestCanonicalBytes(encodedRequest), nil
}

func digestCanonicalBytes(encodedRecord []byte) string {
	digest := sha256.Sum256(encodedRecord)
	return hex.EncodeToString(digest[:])
}
