package v1

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"
)

func DecodeRequest(encodedRequest []byte) (Request, error) {
	trimmedRequest := bytes.TrimSpace(encodedRequest)
	if len(trimmedRequest) == 0 {
		return Request{}, decodeError("empty-json")
	}
	if len(encodedRequest) > MaxRequestBytes {
		return Request{}, decodeError("request-too-large")
	}
	if !utf8.Valid(encodedRequest) {
		return Request{}, decodeError("invalid-utf8")
	}
	if trimmedRequest[0] != '{' {
		return Request{}, decodeError("root-not-object")
	}
	if err := validateJSONStructure(encodedRequest); err != nil {
		return Request{}, err
	}

	decoder := json.NewDecoder(bytes.NewReader(encodedRequest))
	decoder.DisallowUnknownFields()
	var request Request
	if err := decoder.Decode(&request); err != nil {
		return Request{}, decodeError("schema-decode")
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Request{}, err
	}
	if err := ValidateRequest(request); err != nil {
		return Request{}, err
	}
	return request, nil
}

func validateJSONStructure(encodedRequest []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encodedRequest))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return decodeError("malformed-json")
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}

	switch delimiter {
	case '{':
		seenKeys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return decodeError("malformed-json")
			}
			key, ok := keyToken.(string)
			if !ok {
				return decodeError("malformed-json")
			}
			if _, exists := seenKeys[key]; exists {
				return decodeError("duplicate-object-key")
			}
			seenKeys[key] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		return consumeClosingDelimiter(decoder, '}')
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		return consumeClosingDelimiter(decoder, ']')
	default:
		return decodeError("malformed-json")
	}
}

func consumeClosingDelimiter(decoder *json.Decoder, expected json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return decodeError("malformed-json")
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != expected {
		return decodeError("malformed-json")
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); err == io.EOF {
		return nil
	}
	return decodeError("trailing-json")
}
