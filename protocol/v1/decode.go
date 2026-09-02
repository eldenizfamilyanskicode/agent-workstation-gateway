package v1

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

func DecodeRequest(encodedRequest []byte) (Request, error) {
	var request Request
	if err := decodeStrictObject(encodedRequest, MaxRequestBytes, "request", &request); err != nil {
		return Request{}, err
	}
	if err := ValidateRequest(request); err != nil {
		return Request{}, err
	}
	return request, nil
}

func decodeStrictObject(encodedJSON []byte, maximumBytes int, field string, destination any) error {
	if len(encodedJSON) > maximumBytes {
		return decodeError(field, "record-too-large")
	}
	if !utf8.Valid(encodedJSON) {
		return decodeError(field, "invalid-utf8")
	}
	trimmedJSON := bytes.TrimSpace(encodedJSON)
	if len(trimmedJSON) == 0 {
		return decodeError(field, "empty-json")
	}
	if trimmedJSON[0] != '{' {
		return decodeError(field, "root-not-object")
	}
	if err := validateJSONStructure(encodedJSON, field); err != nil {
		return err
	}
	if err := requireJSONFields(encodedJSON, reflect.TypeOf(destination), field); err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(encodedJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return decodeError(field, "schema-decode")
	}
	return requireJSONEOF(decoder, field)
}

func requireJSONFields(encodedJSON []byte, destinationType reflect.Type, field string) error {
	for destinationType.Kind() == reflect.Pointer {
		destinationType = destinationType.Elem()
	}
	return requireJSONFieldsForType(json.RawMessage(encodedJSON), destinationType, field)
}

func requireJSONFieldsForType(encodedJSON json.RawMessage, valueType reflect.Type, field string) error {
	for valueType.Kind() == reflect.Pointer {
		if bytes.Equal(bytes.TrimSpace(encodedJSON), []byte("null")) {
			return nil
		}
		valueType = valueType.Elem()
	}
	if bytes.Equal(bytes.TrimSpace(encodedJSON), []byte("null")) {
		return decodeError(field, "schema-decode")
	}

	switch valueType.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(encodedJSON, &object); err != nil || object == nil {
			return nil
		}
		knownNames := make(map[string]struct{}, valueType.NumField())
		for fieldIndex := 0; fieldIndex < valueType.NumField(); fieldIndex++ {
			structField := valueType.Field(fieldIndex)
			jsonName := strings.Split(structField.Tag.Get("json"), ",")[0]
			if jsonName == "" || jsonName == "-" {
				continue
			}
			knownNames[jsonName] = struct{}{}
		}
		for jsonName := range object {
			if _, known := knownNames[jsonName]; !known {
				return decodeError(field, "schema-decode")
			}
		}
		for fieldIndex := 0; fieldIndex < valueType.NumField(); fieldIndex++ {
			structField := valueType.Field(fieldIndex)
			jsonName := strings.Split(structField.Tag.Get("json"), ",")[0]
			if jsonName == "" || jsonName == "-" {
				continue
			}
			fieldValue, exists := object[jsonName]
			if !exists {
				return decodeError(field, "missing-required-field")
			}
			if err := requireJSONFieldsForType(fieldValue, structField.Type, field); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		var items []json.RawMessage
		if err := json.Unmarshal(encodedJSON, &items); err != nil {
			return nil
		}
		for _, item := range items {
			if err := requireJSONFieldsForType(item, valueType.Elem(), field); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateJSONStructure(encodedJSON []byte, field string) error {
	decoder := json.NewDecoder(bytes.NewReader(encodedJSON))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder, field); err != nil {
		return err
	}
	return requireJSONEOF(decoder, field)
}

func consumeJSONValue(decoder *json.Decoder, field string) error {
	token, err := decoder.Token()
	if err != nil {
		return decodeError(field, "malformed-json")
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
				return decodeError(field, "malformed-json")
			}
			key, ok := keyToken.(string)
			if !ok {
				return decodeError(field, "malformed-json")
			}
			if _, exists := seenKeys[key]; exists {
				return decodeError(field, "duplicate-object-key")
			}
			seenKeys[key] = struct{}{}
			if err := consumeJSONValue(decoder, field); err != nil {
				return err
			}
		}
		return consumeClosingDelimiter(decoder, '}', field)
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder, field); err != nil {
				return err
			}
		}
		return consumeClosingDelimiter(decoder, ']', field)
	default:
		return decodeError(field, "malformed-json")
	}
}

func consumeClosingDelimiter(decoder *json.Decoder, expected json.Delim, field string) error {
	token, err := decoder.Token()
	if err != nil {
		return decodeError(field, "malformed-json")
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != expected {
		return decodeError(field, "malformed-json")
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder, field string) error {
	if _, err := decoder.Token(); err == io.EOF {
		return nil
	}
	return decodeError(field, "trailing-json")
}
