package installconfig

import "fmt"

type Error struct {
	Field string
	Rule  string
}

func (validationFailure *Error) Error() string {
	return fmt.Sprintf("installation config validation failed for %s: %s", validationFailure.Field, validationFailure.Rule)
}

func configError(field string, rule string) error {
	return &Error{Field: field, Rule: rule}
}
