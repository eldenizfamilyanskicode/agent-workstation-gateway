package executionrun

import (
	"context"
	"io"
	"time"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/shellinvoke"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

// NativeLaunch contains only the authority and data required by a native
// launcher. The launcher must enforce the fixed execution identity and must
// not substitute the broker/control identity on failure.
type NativeLaunch struct {
	ExecutionIdentity installconfig.Principal
	WorkingDirectory  string
	ApprovedRoot      string
	Environment       []string
	Capabilities      []installconfig.Capability
	Invocation        shellinvoke.Invocation
}

// Launcher starts a process behind a native identity and process-tree
// boundary. There is intentionally no shared os/exec implementation.
type Launcher interface {
	Start(context.Context, NativeLaunch, io.Writer, io.Writer) (Process, error)
}

// Process owns the complete native process tree. Exit must signal exactly once
// only after the tree has been reaped. TerminateTree must synchronously
// terminate and reap the complete tree before returning.
type Process interface {
	Exit() <-chan ProcessExit
	TerminateTree(context.Context) error
}

type ProcessExit struct {
	Code         int64
	RuntimeError error
}

// ArtifactPlan deliberately excludes the script, shell argument vector, and
// environment. A native collector must read only beneath WorkingDirectory and
// under ExecutionIdentity using native link/reparse protections.
type ArtifactPlan struct {
	ExecutionIdentity installconfig.Principal
	WorkingDirectory  string
	ApprovedRoot      string
	Selections        []v1.ArtifactSelection
}

type ArtifactCollector interface {
	Collect(context.Context, ArtifactPlan) (ArtifactCollection, error)
}

// ArtifactCollection couples report metadata to content handles opened under
// native execution authority. A collection with files requires a Bundle.
type ArtifactCollection struct {
	Manifest v1.ArtifactManifest
	Bundle   ArtifactBundle
}

// ArtifactBundle owns stable collected content until the control response has
// streamed it. Open may expose only exact group/path pairs in its Manifest and
// Close must be idempotent.
type ArtifactBundle interface {
	Open(group string, path string) (io.ReadCloser, error)
	Close() error
}

type Clock interface {
	Now() time.Time
}

type Timer interface {
	Channel() <-chan time.Time
	Stop() bool
}

type TimerFactory interface {
	NewTimer(time.Duration) Timer
}

type Options struct {
	Clock                     Clock
	Timers                    TimerFactory
	TreeTerminationGrace      time.Duration
	ArtifactCollectionTimeout time.Duration
}

type Output struct {
	Report         v1.ExecutionReport
	Stdout         []byte
	Stderr         []byte
	ArtifactBundle ArtifactBundle
}

func (output Output) Close() error {
	if output.ArtifactBundle == nil {
		return nil
	}
	return output.ArtifactBundle.Close()
}
