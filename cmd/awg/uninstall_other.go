//go:build !windows

package main

import (
	"context"
	"fmt"
	"io"
)

func runUninstall(_ context.Context, _ []string, _ io.Writer, stderr io.Writer, _ string) int {
	fmt.Fprintln(stderr, "uninstall is not implemented on this platform")
	return 1
}
