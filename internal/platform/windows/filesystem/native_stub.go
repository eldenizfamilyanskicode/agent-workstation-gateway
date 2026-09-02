//go:build !windows

package filesystem

import (
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/filesystemprovision"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
)

type Native struct{}

type Error struct {
	Rule string
}

func (failure *Error) Error() string {
	return "Windows workload filesystem boundary unavailable: " + failure.Rule
}

func New(installconfig.Config) (*Native, error) {
	return nil, &Error{Rule: "unsupported-platform"}
}

func (*Native) ConvergeApprovedRoot(string, string) (filesystemprovision.Change, error) {
	return nil, &Error{Rule: "unsupported-platform"}
}

func (*Native) ConvergeIsolatedRoot(string, string) (filesystemprovision.Change, error) {
	return nil, &Error{Rule: "unsupported-platform"}
}
