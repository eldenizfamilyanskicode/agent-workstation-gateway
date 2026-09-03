//go:build !windows

package main

import (
	"context"
	"fmt"
	"io"
)

func runExecuteLocal(_ context.Context, _ []string, _ io.Writer, stderr io.Writer) int {
	fmt.Fprintln(stderr, "execute-local is only available on Windows")
	return 2
}
