//go:build windows

package process

import (
	"strings"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
)

func validateTokenIdentity(token windows.Token, expected installconfig.Principal) error {
	if token == 0 {
		return boundaryError("token-required")
	}
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return boundaryError("token-user-query-failed")
	}
	primaryGroup, err := token.GetTokenPrimaryGroup()
	if err != nil || primaryGroup == nil || primaryGroup.PrimaryGroup == nil {
		return boundaryError("token-primary-group-query-failed")
	}
	if !strings.EqualFold(user.User.Sid.String(), expected.Identifier) {
		return boundaryError("token-user-mismatch")
	}
	if !strings.EqualFold(primaryGroup.PrimaryGroup.String(), expected.PrimaryGroupIdentifier) {
		return boundaryError("token-primary-group-mismatch")
	}
	return nil
}

// ValidateTokenIdentity lets other native broker boundaries independently
// require the configured execution user and primary group on a token lease.
func ValidateTokenIdentity(token windows.Token, expected installconfig.Principal) error {
	return validateTokenIdentity(token, expected)
}
