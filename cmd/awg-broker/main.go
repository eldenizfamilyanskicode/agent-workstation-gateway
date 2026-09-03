package main

import "os"

// gatewaySourceSHA is set only by the trusted release build with
// -ldflags=-X=main.gatewaySourceSHA=<lowercase-40-hex-commit>.
var gatewaySourceSHA string

type serviceStarter func(string, string) error

func main() {
	os.Exit(run(os.Args[1:], gatewaySourceSHA, startPlatformService))
}

func run(args []string, sourceSHA string, start serviceStarter) int {
	if start == nil || len(args) != 2 || args[0] != "--installation-root" || args[1] == "" {
		return 1
	}
	if err := start(args[1], sourceSHA); err != nil {
		return 1
	}
	return 0
}
