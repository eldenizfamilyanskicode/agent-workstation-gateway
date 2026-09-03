//go:build !windows && !linux

package main

import (
	"context"
	"fmt"
	"io"
)

func runInstallMutation(_ context.Context, _ []string, _ io.Writer, stderr io.Writer, _ string) int {
	fmt.Fprintln(stderr, "mutating install is not implemented on this platform")
	return 1
}
