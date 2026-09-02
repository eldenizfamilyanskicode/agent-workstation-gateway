package shellinvoke

import (
	"bytes"
	"errors"
	"io"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionpolicy"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

var ErrInvalidLaunchPlan = errors.New("invalid shell launch plan")
var ErrUnsupportedShell = errors.New("unsupported shell")

// Invocation is a closed shell startup description. The requester script is
// available only as stdin data and is never included in the executable or
// argument vector.
type Invocation struct {
	executable string
	arguments  []string
	script     []byte
}

func Build(plan executionpolicy.LaunchPlan) (Invocation, error) {
	if plan.Executable == "" || plan.Script == "" {
		return Invocation{}, ErrInvalidLaunchPlan
	}
	arguments, ok := shellArguments(plan.Shell)
	if !ok {
		return Invocation{}, ErrUnsupportedShell
	}
	return Invocation{
		executable: plan.Executable,
		arguments:  arguments,
		script:     []byte(plan.Script),
	}, nil
}

func (invocation Invocation) Executable() string {
	return invocation.executable
}

func (invocation Invocation) Arguments() []string {
	return append([]string(nil), invocation.arguments...)
}

func (invocation Invocation) ScriptReader() io.Reader {
	return bytes.NewReader(invocation.script)
}

func (invocation Invocation) ScriptBytes() int {
	return len(invocation.script)
}

func shellArguments(shell v1.Shell) ([]string, bool) {
	switch shell {
	case v1.ShellBash, v1.ShellGitBash:
		return []string{"--noprofile", "--norc", "-s"}, true
	case v1.ShellPowerShell, v1.ShellPwsh:
		return []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-"}, true
	case v1.ShellCmd:
		return []string{"/D", "/Q"}, true
	default:
		return nil, false
	}
}
