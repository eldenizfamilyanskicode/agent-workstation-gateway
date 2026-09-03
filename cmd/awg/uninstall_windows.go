//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/githubcontrol"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/doctor"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/uninstaller"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

func runUninstall(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, sourceSHA string) int {
	flags := flag.NewFlagSet("awg uninstall", flag.ContinueOnError)
	flags.SetOutput(stderr)
	installationRoot := flags.String("installation-root", "", "protected AWG installation root")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *installationRoot == "" {
		fmt.Fprintln(stderr, "uninstall requires --installation-root")
		return 2
	}
	executable, executableErr := os.Executable()
	absoluteExecutable, absoluteErr := filepath.Abs(executable)
	if executableErr != nil || absoluteErr != nil || platformpath.Contains(platformpath.Windows, *installationRoot, filepath.Clean(absoluteExecutable)) {
		fmt.Fprintln(stderr, "run uninstall from the matching release executable outside the installation root")
		return 1
	}
	_, installation, err := doctor.InspectInstalled(ctx, *installationRoot, sourceSHA)
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
	if err := uninstaller.Run(ctx, *installationRoot, sourceSHA, client); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, "gateway uninstalled; the private repository and ledger were preserved")
	return 0
}
