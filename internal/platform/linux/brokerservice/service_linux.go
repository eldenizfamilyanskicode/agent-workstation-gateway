//go:build linux

package brokerservice

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/linux/brokerhost"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/sourceversion"
)

const ServiceName = "agent-workstation-gateway-broker.service"

type Error struct{ Rule string }

func (failure *Error) Error() string {
	return fmt.Sprintf("Linux broker service failed: %s", failure.Rule)
}

func Run(installationRoot, sourceSHA string) error {
	if os.Geteuid() != 0 {
		return serviceError("root-service-required")
	}
	if _, err := installplan.LinuxLayout(installationRoot); err != nil || !sourceversion.IsCanonicalGitSHA(sourceSHA) {
		return serviceError("startup-input-invalid")
	}
	runtime, err := brokerhost.New(installationRoot, sourceSHA)
	if err != nil {
		return serviceError("runtime-create-failed")
	}
	defer runtime.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	for ctx.Err() == nil {
		err := runtime.HandleOne(ctx)
		if ctx.Err() != nil {
			break
		}
		if err != nil && !brokerhost.IsRecoverableConnectionError(err) {
			return serviceError("runtime-failed")
		}
	}
	return runtime.Close()
}

func serviceError(rule string) error { return &Error{Rule: rule} }
