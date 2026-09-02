package brokerproto

import "fmt"

type Error struct {
	Field string
	Rule  string
}

func (validationFailure *Error) Error() string {
	return fmt.Sprintf("broker protocol validation failed for %s: %s", validationFailure.Field, validationFailure.Rule)
}

func protocolError(field string, rule string) error {
	return &Error{Field: field, Rule: rule}
}
