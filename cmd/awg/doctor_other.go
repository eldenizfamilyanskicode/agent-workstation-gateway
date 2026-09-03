//go:build !windows

package main

import (
	"context"
	"fmt"
	"io"
)

func runDoctor(_ context.Context, _ []string, _ io.Writer, stderr io.Writer, _ string) int {
	fmt.Fprintln(stderr, "doctor is not implemented on this platform")
	return 1
}
