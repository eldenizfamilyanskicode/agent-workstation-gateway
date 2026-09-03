//go:build windows

package main

import "github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/brokerservice"

func startPlatformService(installationRoot string, sourceSHA string) error {
	return brokerservice.Run(installationRoot, sourceSHA)
}
