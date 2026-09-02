package strictjson

import "fmt"

type Error struct {
	Rule string
}

func (decodeFailure *Error) Error() string {
	return fmt.Sprintf("strict JSON decode failed: %s", decodeFailure.Rule)
}

func decodeError(rule string) error {
	return &Error{Rule: rule}
}
