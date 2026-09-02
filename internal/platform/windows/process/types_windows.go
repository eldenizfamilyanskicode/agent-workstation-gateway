//go:build windows

package process

import (
	"context"
	"fmt"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
)

type Error struct {
	Rule string
}

func (failure *Error) Error() string {
	return fmt.Sprintf("Windows process boundary failed: %s", failure.Rule)
}

// TokenLease owns a primary token and any profile/logon state that must remain
// live until the launched process tree has been reaped.
type TokenLease interface {
	Token() windows.Token
	Close() error
}

// TokenSource obtains only the preconfigured execution identity. Account
// credential storage and profile loading are implemented by the installed
// broker, not selected by request data.
type TokenSource interface {
	Acquire(context.Context, installconfig.Principal) (TokenLease, error)
}

func boundaryError(rule string) error {
	return &Error{Rule: rule}
}
