//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/controlclient"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/linux/brokeripc"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/linux/controlresponse"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

type linuxSocketDialer struct{}

func (linuxSocketDialer) Dial(ctx context.Context) (controlclient.Transport, error) {
	return brokeripc.Dial(ctx)
}

func runExecuteLocal(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("awg execute-local", flag.ContinueOnError)
	flags.SetOutput(stderr)
	acceptedPath := flags.String("accepted", "", "path to a canonical accepted-request record")
	attemptID := flags.String("attempt", "", "unique local execution attempt identifier")
	outputPath := flags.String("output", "", "create-new final response directory")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *acceptedPath == "" || *attemptID == "" || *outputPath == "" {
		fmt.Fprintln(stderr, "execute-local requires --accepted, --attempt, and --output")
		return 2
	}
	encoded, err := readBounded(*acceptedPath, v1.MaxAcceptedRecordBytes)
	if err != nil {
		fmt.Fprintln(stderr, "could not read bounded accepted request")
		return 1
	}
	accepted, err := v1.DecodeAcceptedRequestRecord(encoded)
	if err != nil {
		fmt.Fprintln(stderr, "accepted request is invalid")
		return 1
	}
	destination, err := controlresponse.New(*outputPath)
	if err != nil {
		fmt.Fprintln(stderr, "response destination is unavailable")
		return 1
	}
	defer destination.Abort()
	if err := controlclient.Exchange(ctx, linuxSocketDialer{}, accepted, *attemptID, destination); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "response published")
	return 0
}

var _ controlclient.Dialer = linuxSocketDialer{}
