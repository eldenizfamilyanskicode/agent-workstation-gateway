//go:build windows

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/githubcontrol"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/doctor"
)

func runDoctor(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, version, sourceSHA string) int {
	flags := flag.NewFlagSet("awg doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	installationRoot := flags.String("installation-root", "", "protected AWG installation root")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *installationRoot == "" {
		fmt.Fprintln(stderr, "doctor requires --installation-root")
		return 2
	}
	report, installation, err := doctor.CheckLocal(ctx, *installationRoot, sourceSHA)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	token, err := acquireGitHubToken(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "authenticated GitHub CLI session is unavailable")
		return 1
	}
	defer clearBytes(token)
	client, err := githubcontrol.New(token, installation.Metadata.ControlRepository)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer client.Close()
	if err := client.VerifyExclusivePrivate(ctx); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := client.VerifyRunner(ctx, installation.Metadata.RunnerName); err != nil {
		fmt.Fprintln(stderr, "registered runner identity is invalid")
		return 1
	}
	for _, file := range installation.Metadata.ControlFiles {
		if err := client.VerifyOwnedControlFile(ctx, file.Path, file.SHA256); err != nil {
			fmt.Fprintln(stderr, "control repository content is invalid")
			return 1
		}
	}
	report.PrivateRepository = true
	report.ExclusiveReaders = true
	report.Version = version
	report.SourceSHA = sourceSHA
	encoded, err := json.Marshal(report)
	if err != nil {
		fmt.Fprintln(stderr, "doctor report encoding failed")
		return 1
	}
	_, _ = stdout.Write(append(encoded, '\n'))
	return 0
}
