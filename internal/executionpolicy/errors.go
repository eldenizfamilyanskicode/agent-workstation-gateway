package executionpolicy

import "fmt"

type Error struct {
	Field string
	Rule  string
}

func (authorizationFailure *Error) Error() string {
	return fmt.Sprintf("execution policy authorization failed for %s: %s", authorizationFailure.Field, authorizationFailure.Rule)
}

func policyError(field string, rule string) error {
	return &Error{Field: field, Rule: rule}
}
