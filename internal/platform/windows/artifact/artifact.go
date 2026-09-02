package artifact

import "fmt"

type Error struct {
	Rule  string
	Cause error
}

func (failure *Error) Error() string {
	return fmt.Sprintf("Windows artifact boundary failed: %s", failure.Rule)
}

func (failure *Error) Unwrap() error { return failure.Cause }

func artifactError(rule string) error {
	return &Error{Rule: rule}
}

func artifactCause(rule string, cause error) error {
	return &Error{Rule: rule, Cause: cause}
}
