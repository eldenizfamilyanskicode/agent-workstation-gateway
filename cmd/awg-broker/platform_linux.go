//go:build linux

package main

import (
	linuxartifact "github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/linux/artifact"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/linux/brokerservice"
	linuxprocess "github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/linux/process"
)

func startPlatformService(installationRoot, sourceSHA string) error {
	return brokerservice.Run(installationRoot, sourceSHA)
}

func runPlatformHelper(args []string) (bool, int) {
	if len(args) == 0 {
		return false, 0
	}
	switch args[0] {
	case linuxprocess.HelperOperation:
		return true, linuxprocess.RunHelper(args)
	case linuxartifact.HelperOperation:
		return true, linuxartifact.RunHelper(args)
	default:
		return false, 0
	}
}
