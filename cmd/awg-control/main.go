package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/controlplane"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/githubcontrol"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/sourceversion"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

// controlSourceSHA is set by the trusted release build with
// -ldflags=-X=main.controlSourceSHA=<lowercase-40-hex-commit>.
var controlVersion = "devel"
var controlSourceSHA string

type consumeEnvironment func(string) (string, bool)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	consume := func(name string) (string, bool) {
		value, exists := os.LookupEnv(name)
		_ = os.Unsetenv(name)
		return value, exists
	}
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, consume, controlSourceSHA, time.Now))
}

func run(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, consume consumeEnvironment, sourceSHA string, now func() time.Time) int {
	if ctx == nil || stdout == nil || stderr == nil || consume == nil || now == nil {
		return 2
	}
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}
	switch args[0] {
	case "accept":
		return runAccept(ctx, args[1:], stdout, stderr, consume, sourceSHA, now)
	case "finalize":
		return runFinalize(ctx, args[1:], stdout, stderr, consume, now)
	case "publish":
		return runPublish(ctx, args[1:], stdout, stderr, consume)
	case "version":
		return runControlVersion(args[1:], stdout, stderr, controlVersion, sourceSHA)
	default:
		fmt.Fprintln(stderr, "unknown awg-control command")
		return 2
	}
}

func printUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage:")
	fmt.Fprintln(writer, "  awg-control accept --event <path> --output <path>")
	fmt.Fprintln(writer, "  awg-control finalize --accepted <path> --report <path> --output <path>")
	fmt.Fprintln(writer, "  awg-control publish --kind accepted|result --input <path>")
	fmt.Fprintln(writer, "  awg-control version")
}

func runControlVersion(args []string, stdout io.Writer, stderr io.Writer, version, sourceSHA string) int {
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
	encoded, err := json.Marshal(struct {
		Version   string `json:"version"`
		SourceSHA string `json:"source_sha"`
	}{Version: version, SourceSHA: sourceSHA})
	if err != nil {
		fmt.Fprintln(stderr, "version encoding failed")
		return 1
	}
	_, _ = stdout.Write(append(encoded, '\n'))
	return 0
}

func runAccept(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, consume consumeEnvironment, sourceSHA string, now func() time.Time) int {
	flags := flag.NewFlagSet("awg-control accept", flag.ContinueOnError)
	flags.SetOutput(stderr)
	eventPath := flags.String("event", "", "immutable GitHub issue event path")
	outputPath := flags.String("output", "", "create-new accepted record path")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *eventPath == "" || *outputPath == "" {
		fmt.Fprintln(stderr, "accept requires --event and --output")
		return 2
	}
	encoded, err := readBounded(*eventPath, controlplane.MaxEventBytes)
	if err != nil {
		fmt.Fprintln(stderr, "could not read bounded event")
		return 1
	}
	workflow, ok := consumeWorkflow(consume)
	if !ok {
		fmt.Fprintln(stderr, "GitHub workflow context is unavailable")
		return 1
	}
	record, err := controlplane.Accept(encoded, workflow, sourceSHA, now())
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	canonical, err := v1.MarshalCanonicalAcceptedRequestRecord(record)
	if err != nil || writeNew(*outputPath, canonical) != nil {
		fmt.Fprintln(stderr, "could not publish local accepted record")
		return 1
	}
	fmt.Fprintln(stdout, "request accepted")
	return 0
}

func runFinalize(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, consume consumeEnvironment, now func() time.Time) int {
	flags := flag.NewFlagSet("awg-control finalize", flag.ContinueOnError)
	flags.SetOutput(stderr)
	acceptedPath := flags.String("accepted", "", "canonical accepted record path")
	reportPath := flags.String("report", "", "canonical execution report path")
	outputPath := flags.String("output", "", "create-new result record path")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *acceptedPath == "" || *reportPath == "" || *outputPath == "" {
		fmt.Fprintln(stderr, "finalize requires --accepted, --report, and --output")
		return 2
	}
	acceptedBytes, acceptedErr := readBounded(*acceptedPath, v1.MaxAcceptedRecordBytes)
	reportBytes, reportErr := readBounded(*reportPath, v1.MaxExecutionReportBytes)
	if acceptedErr != nil || reportErr != nil {
		fmt.Fprintln(stderr, "could not read bounded finalization input")
		return 1
	}
	accepted, acceptedErr := v1.DecodeAcceptedRequestRecord(acceptedBytes)
	report, reportErr := v1.DecodeExecutionReport(reportBytes)
	if acceptedErr != nil || reportErr != nil {
		fmt.Fprintln(stderr, "finalization input is invalid")
		return 1
	}
	workflow, ok := consumeWorkflow(consume)
	if !ok {
		fmt.Fprintln(stderr, "GitHub workflow context is unavailable")
		return 1
	}
	result, err := controlplane.Finalize(accepted, report, workflow, now())
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	canonical, err := v1.MarshalCanonicalResultRecord(result)
	if err != nil || writeNew(*outputPath, canonical) != nil {
		fmt.Fprintln(stderr, "could not publish local result record")
		return 1
	}
	fmt.Fprintln(stdout, "result finalized")
	return 0
}

func runPublish(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, consume consumeEnvironment) int {
	flags := flag.NewFlagSet("awg-control publish", flag.ContinueOnError)
	flags.SetOutput(stderr)
	kind := flags.String("kind", "", "accepted or result")
	inputPath := flags.String("input", "", "canonical record path")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || (*kind != "accepted" && *kind != "result") || *inputPath == "" {
		fmt.Fprintln(stderr, "publish requires --kind accepted|result and --input")
		return 2
	}
	repository, repositoryOK := consume("GITHUB_REPOSITORY")
	tokenText, tokenOK := consume("GITHUB_TOKEN")
	token := []byte(tokenText)
	defer clear(token)
	if !repositoryOK || !tokenOK {
		fmt.Fprintln(stderr, "GitHub publication context is unavailable")
		return 1
	}
	client, err := githubcontrol.New(token, repository)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer client.Close()
	maximum := v1.MaxAcceptedRecordBytes
	if *kind == "result" {
		maximum = v1.MaxResultRecordBytes
	}
	encoded, err := readBounded(*inputPath, maximum)
	if err != nil {
		fmt.Fprintln(stderr, "could not read bounded publication input")
		return 1
	}
	if *kind == "accepted" {
		record, decodeErr := v1.DecodeAcceptedRequestRecord(encoded)
		if decodeErr != nil {
			fmt.Fprintln(stderr, "publication input is invalid")
			return 1
		}
		err = client.PublishAccepted(ctx, record)
	} else {
		record, decodeErr := v1.DecodeResultRecord(encoded)
		if decodeErr != nil {
			fmt.Fprintln(stderr, "publication input is invalid")
			return 1
		}
		err = client.PublishResult(ctx, record)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, "record published")
	return 0
}

func consumeWorkflow(consume consumeEnvironment) (controlplane.WorkflowContext, bool) {
	names := []string{"GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_EVENT_NAME", "GITHUB_SHA"}
	values := make([]string, len(names))
	for index, name := range names {
		value, exists := consume(name)
		if !exists || value == "" {
			return controlplane.WorkflowContext{}, false
		}
		values[index] = value
	}
	return controlplane.WorkflowContext{
		Repository: values[0], RunID: values[1], RunAttempt: values[2], EventName: values[3],
		EventAction: "opened", HeadSHA: values[4],
	}, true
}

func readBounded(path string, maximum int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(content) > maximum {
		return nil, fmt.Errorf("bounded read failed")
	}
	return content, nil
}

func writeNew(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(content)
	closeErr := file.Close()
	if writeErr != nil || written != len(content) || closeErr != nil {
		_ = os.Remove(path)
		return fmt.Errorf("write failed")
	}
	return nil
}

func clear(buffer []byte) {
	for index := range buffer {
		buffer[index] = 0
	}
}
