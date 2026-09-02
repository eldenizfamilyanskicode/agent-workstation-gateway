package strictjson

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

func DecodeObject(encoded []byte, maximumBytes int, destination any) error {
	if len(encoded) > maximumBytes {
		return decodeError("record-too-large")
	}
	if !utf8.Valid(encoded) {
		return decodeError("invalid-utf8")
	}
	trimmed := bytes.TrimSpace(encoded)
	if len(trimmed) == 0 {
		return decodeError("empty-json")
	}
	if trimmed[0] != '{' {
		return decodeError("root-not-object")
	}
	destinationType := reflect.TypeOf(destination)
	if destinationType == nil || destinationType.Kind() != reflect.Pointer || destinationType.Elem().Kind() != reflect.Struct {
		return decodeError("invalid-destination")
	}
	if err := validateStructure(encoded); err != nil {
		return err
	}
	if err := requireExactFields(json.RawMessage(encoded), destinationType.Elem()); err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(encoded))
	if err := decoder.Decode(destination); err != nil {
		return decodeError("schema-decode")
	}
	return requireEOF(decoder)
}

func validateStructure(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := consumeValue(decoder); err != nil {
		return err
	}
	return requireEOF(decoder)
}

func consumeValue(decoder *json.Decoder) error {
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
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return decodeError("malformed-json")
			}
			key, ok := keyToken.(string)
			if !ok {
				return decodeError("malformed-json")
			}
			if _, exists := seen[key]; exists {
				return decodeError("duplicate-object-key")
			}
			seen[key] = struct{}{}
			if err := consumeValue(decoder); err != nil {
				return err
			}
		}
		return consumeClosingDelimiter(decoder, '}')
	case '[':
		for decoder.More() {
			if err := consumeValue(decoder); err != nil {
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

func requireEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); err == io.EOF {
		return nil
	}
	return decodeError("trailing-json")
}

func requireExactFields(encoded json.RawMessage, valueType reflect.Type) error {
	for valueType.Kind() == reflect.Pointer {
		if isNull(encoded) {
			return nil
		}
		valueType = valueType.Elem()
	}
	if isNull(encoded) {
		return decodeError("schema-decode")
	}

	switch valueType.Kind() {
	case reflect.Struct:
		return requireExactStructFields(encoded, valueType)
	case reflect.Slice, reflect.Array:
		var items []json.RawMessage
		if err := json.Unmarshal(encoded, &items); err != nil {
			return nil
		}
		for _, item := range items {
			if err := requireExactFields(item, valueType.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

func requireExactStructFields(encoded json.RawMessage, valueType reflect.Type) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &object); err != nil || object == nil {
		return nil
	}
	known := make(map[string]reflect.StructField, valueType.NumField())
	for index := 0; index < valueType.NumField(); index++ {
		field := valueType.Field(index)
		jsonName := strings.Split(field.Tag.Get("json"), ",")[0]
		if jsonName != "" && jsonName != "-" {
			known[jsonName] = field
		}
	}
	for jsonName := range object {
		if _, exists := known[jsonName]; !exists {
			return decodeError("unknown-field")
		}
	}
	for jsonName, field := range known {
		fieldValue, exists := object[jsonName]
		if !exists {
			return decodeError("missing-required-field")
		}
		if err := requireExactFields(fieldValue, field.Type); err != nil {
			return err
		}
	}
	return nil
}

func isNull(encoded json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(encoded), []byte("null"))
}
