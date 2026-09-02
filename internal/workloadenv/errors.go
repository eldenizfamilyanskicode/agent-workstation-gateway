package workloadenv

import "fmt"

type Error struct {
	Field string
	Rule  string
}

func (validationFailure *Error) Error() string {
	return fmt.Sprintf("workload environment construction failed for %s: %s", validationFailure.Field, validationFailure.Rule)
}

func environmentError(field string, rule string) error {
	return &Error{Field: field, Rule: rule}
}
