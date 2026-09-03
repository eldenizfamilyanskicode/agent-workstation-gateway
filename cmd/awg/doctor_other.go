//go:build !windows && !linux

package main

import (
	"context"
	"fmt"
	"io"
)

func runDoctor(_ context.Context, _ []string, _ io.Writer, stderr io.Writer, _, _ string) int {
	fmt.Fprintln(stderr, "doctor is not implemented on this platform")
	return 1
}
