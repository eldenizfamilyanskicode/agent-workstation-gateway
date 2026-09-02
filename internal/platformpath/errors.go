package platformpath

import "fmt"

type Error struct {
	Rule string
}

func (validationFailure *Error) Error() string {
	return fmt.Sprintf("platform path validation failed: %s", validationFailure.Rule)
}

func pathError(rule string) error {
	return &Error{Rule: rule}
}
