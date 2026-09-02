package v1

import "fmt"

type ErrorKind string

const (
	ErrorKindDecode     ErrorKind = "decode"
	ErrorKindValidation ErrorKind = "validation"
)

type ProtocolError struct {
	Kind  ErrorKind
	Field string
	Rule  string
}

func (protocolError *ProtocolError) Error() string {
	return fmt.Sprintf("protocol %s failed for %s: %s", protocolError.Kind, protocolError.Field, protocolError.Rule)
}

func decodeError(rule string) error {
	return &ProtocolError{Kind: ErrorKindDecode, Field: "request", Rule: rule}
}

func validationError(field string, rule string) error {
	return &ProtocolError{Kind: ErrorKindValidation, Field: field, Rule: rule}
}
