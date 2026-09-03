package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/sourceversion"
)

// gatewayVersion and gatewaySourceSHA are set by the trusted release build.
var gatewayVersion = "devel"

// gatewaySourceSHA is set by the trusted release build with
// -ldflags=-X=main.gatewaySourceSHA=<lowercase-40-hex-commit>.
var gatewaySourceSHA string

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	if ctx == nil || stdout == nil || stderr == nil {
		return 2
	}
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}
	switch args[0] {
	case "install":
		return runInstall(ctx, args[1:], stdout, stderr)
	case "execute-local":
		return runExecuteLocal(ctx, args[1:], stdout, stderr)
	case "doctor":
		return runDoctor(ctx, args[1:], stdout, stderr, gatewayVersion, gatewaySourceSHA)
	case "uninstall":
		return runUninstall(ctx, args[1:], stdout, stderr, gatewaySourceSHA)
	case "version":
		return runVersion(args[1:], stdout, stderr, gatewayVersion, gatewaySourceSHA)
	default:
		fmt.Fprintln(stderr, "unknown awg command")
		return 2
	}
}

func printUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage:")
	fmt.Fprintln(writer, "  awg install --dry-run --spec <path>")
	fmt.Fprintln(writer, "  awg install --spec <path> --repository <owner/name> --broker-image <path> --control-image <path> --runner-archive <path> --hosted-control-url <url> --hosted-control-sha256 <digest> [--create-repository]")
	fmt.Fprintln(writer, "  awg execute-local --accepted <path> --attempt <id> --output <path>")
	fmt.Fprintln(writer, "  awg doctor --installation-root <path>")
	fmt.Fprintln(writer, "  awg uninstall --installation-root <path>")
	fmt.Fprintln(writer, "  awg version")
}

func runVersion(args []string, stdout io.Writer, stderr io.Writer, version, sourceSHA string) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "version accepts no arguments")
		return 2
	}
	if version == "" {
		version = "devel"
	}
	if !sourceversion.IsCanonicalGitSHA(sourceSHA) {
		sourceSHA = "unknown"
	}
	record := struct {
		Version   string `json:"version"`
		SourceSHA string `json:"source_sha"`
	}{Version: version, SourceSHA: sourceSHA}
	encoded, err := json.Marshal(record)
	if err != nil {
		fmt.Fprintln(stderr, "version encoding failed")
		return 1
	}
	_, _ = stdout.Write(append(encoded, '\n'))
	return 0
}

func runInstall(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	if !containsArgument(args, "--dry-run") {
		return runInstallMutation(ctx, args, stdout, stderr, gatewaySourceSHA)
	}
	flags := flag.NewFlagSet("awg install", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dryRun := flags.Bool("dry-run", false, "validate and print the bounded installation plan without mutation")
	specPath := flags.String("spec", "", "path to a platform install specification")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || !*dryRun || *specPath == "" {
		fmt.Fprintln(stderr, "install currently requires --dry-run and exactly one --spec path")
		return 2
	}
	select {
	case <-ctx.Done():
		fmt.Fprintln(stderr, "install planning cancelled")
		return 1
	default:
	}
	encoded, err := readBounded(*specPath, installplan.MaxSpecBytes)
	if err != nil {
		fmt.Fprintln(stderr, "could not read bounded install specification")
		return 1
	}
	specification, err := installplan.Decode(encoded)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	plan, err := installplan.Build(specification)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	encodedPlan, err := installplan.MarshalPlan(plan)
	if err != nil {
		fmt.Fprintln(stderr, "could not encode installation plan")
		return 1
	}
	if _, err := stdout.Write(append(encodedPlan, '\n')); err != nil {
		fmt.Fprintln(stderr, "could not write installation plan")
		return 1
	}
	return 0
}

func containsArgument(args []string, expected string) bool {
	for _, argument := range args {
		if argument == expected {
			return true
		}
	}
	return false
}

func readBounded(path string, maximum int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(encoded) > maximum {
		return nil, fmt.Errorf("bounded read failed")
	}
	return encoded, nil
}
