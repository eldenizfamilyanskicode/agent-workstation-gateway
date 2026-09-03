//go:build !windows && !linux

package main

import "errors"

func startPlatformService(string, string) error {
	return errors.New("awg-broker is not implemented on this platform")
}
