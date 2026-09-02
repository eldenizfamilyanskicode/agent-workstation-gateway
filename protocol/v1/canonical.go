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
	encodedRequest, err := json.Marshal(request)
	if err != nil {
		return nil, decodeError("canonical-encode")
	}
	if len(encodedRequest) > MaxRequestBytes {
		return nil, validationError("request", "canonical-size-limit")
	}
	return encodedRequest, nil
}

func DigestRequest(request Request) (string, error) {
	encodedRequest, err := MarshalCanonicalRequest(request)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encodedRequest)
	return hex.EncodeToString(digest[:]), nil
}
