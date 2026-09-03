//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os/exec"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/githubcontrol"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installmetadata"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/linux/installer"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/runnerpackage"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/runnerregistration"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/sourceversion"
	controltemplate "github.com/eldenizfamilyanskicode/agent-workstation-gateway/templates/control-repository"
)

const maxLinuxGitHubTokenOutput = 4096

func runInstallMutation(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, sourceSHA string) int {
	flags := flag.NewFlagSet("awg install", flag.ContinueOnError)
	flags.SetOutput(stderr)
	specPath := flags.String("spec", "", "path to a Linux install specification")
	repositoryName := flags.String("repository", "", "dedicated personal private control repository")
	createRepository := flags.Bool("create-repository", false, "create and initialize the private control repository")
	brokerPath := flags.String("broker-image", "", "pinned awg-broker Linux release image")
	controlPath := flags.String("control-image", "", "pinned awg Linux release image")
	runnerPath := flags.String("runner-archive", "", "pinned official Linux x64 runner archive")
	hostedControlURL := flags.String("hosted-control-url", "", "pinned awg-control Linux x64 release URL")
	hostedControlDigest := flags.String("hosted-control-sha256", "", "pinned awg-control Linux x64 SHA-256")
	runnerName := flags.String("runner-name", "awg-linux-x64", "dedicated runner name")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *specPath == "" || *repositoryName == "" || *brokerPath == "" ||
		*controlPath == "" || *runnerPath == "" || *hostedControlURL == "" || *hostedControlDigest == "" || *runnerName == "" {
		fmt.Fprintln(stderr, "install requires the specification, private repository, pinned release images, and hosted control digest")
		return 2
	}
	if ctx == nil || !sourceversion.IsCanonicalGitSHA(sourceSHA) {
		fmt.Fprintln(stderr, "trusted installation inputs are unavailable")
		return 1
	}
	specificationBytes, err := readBounded(*specPath, installplan.MaxSpecBytes)
	if err != nil {
		fmt.Fprintln(stderr, "could not read bounded install specification")
		return 1
	}
	specification, err := installplan.Decode(specificationBytes)
	if err != nil || specification.Platform != "linux" {
		fmt.Fprintln(stderr, "Linux install specification is invalid")
		return 1
	}
	brokerImage, brokerErr := readBounded(*brokerPath, 128*1024*1024)
	controlImage, controlErr := readBounded(*controlPath, 128*1024*1024)
	runnerArchive, runnerErr := readBounded(*runnerPath, runnerpackage.MaxArchiveBytes)
	if brokerErr != nil || controlErr != nil || runnerErr != nil || installer.ValidateReleaseImages(sourceSHA, brokerImage, controlImage) != nil {
		fmt.Fprintln(stderr, "release image verification failed")
		return 1
	}
	runnerImage, err := runnerpackage.InspectPinnedLinuxX64(runnerArchive)
	if err != nil {
		fmt.Fprintln(stderr, "runner archive verification failed")
		return 1
	}
	rendered, err := controltemplate.Render(controltemplate.Config{
		GatewaySourceSHA: sourceSHA, ControlBinaryURL: *hostedControlURL,
		ControlBinarySHA256: *hostedControlDigest, InstallationRoot: specification.InstallationRoot,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	token, err := acquireLinuxGitHubToken(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "authenticated GitHub CLI session is unavailable")
		return 1
	}
	defer clearLinuxBytes(token)
	github, err := githubcontrol.New(token, *repositoryName)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer github.Close()
	if *createRepository {
		if err := github.CreatePersonalPrivate(ctx); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	if err := github.VerifyExclusivePrivate(ctx); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	controlFiles := make([]installmetadata.ControlFile, 0, len(rendered))
	for _, file := range rendered {
		created, err := github.EnsureControlFile(ctx, file.Path, file.Content)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		digest := sha256.Sum256(file.Content)
		controlFiles = append(controlFiles, installmetadata.ControlFile{Path: file.Path, SHA256: hex.EncodeToString(digest[:]), Owned: created})
	}
	registrationToken, err := github.RegistrationToken(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "runner registration token is unavailable")
		return 1
	}
	defer clearLinuxBytes(registrationToken)
	removalToken, err := github.RemovalToken(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "runner removal token is unavailable")
		return 1
	}
	defer clearLinuxBytes(removalToken)
	repository, err := runnerregistration.VerifyPrivateRepository(*repositoryName, true)
	if err != nil {
		fmt.Fprintln(stderr, "private repository binding failed")
		return 1
	}
	if err := installer.Provision(ctx, installer.Input{
		Specification: specification, GatewaySourceSHA: sourceSHA, BrokerImage: brokerImage, ControlImage: controlImage, RunnerImage: runnerImage,
		RunnerRegistration: runnerregistration.Request{Repository: repository, RunnerName: *runnerName, RegistrationToken: registrationToken, RemovalToken: removalToken},
		Metadata: installmetadata.Metadata{MetadataVersion: installmetadata.Version, Platform: specification.Platform, InstallationRoot: specification.InstallationRoot,
			ControlRepository: *repositoryName, RunnerName: *runnerName, GatewaySourceSHA: sourceSHA, ControlFiles: controlFiles},
	}); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, "gateway installed")
	return 0
}

func acquireLinuxGitHubToken(ctx context.Context) ([]byte, error) {
	command := exec.CommandContext(ctx, "gh", "auth", "token", "--hostname", "github.com")
	command.Stderr = io.Discard
	pipe, err := command.StdoutPipe()
	if err != nil || command.Start() != nil {
		return nil, fmt.Errorf("GitHub token acquisition failed")
	}
	encoded, readErr := io.ReadAll(io.LimitReader(pipe, maxLinuxGitHubTokenOutput+1))
	waitErr := command.Wait()
	encoded = bytes.TrimSpace(encoded)
	if readErr != nil || waitErr != nil || len(encoded) < 16 || len(encoded) > maxLinuxGitHubTokenOutput || bytes.ContainsAny(encoded, "\x00\r\n\t ") {
		clearLinuxBytes(encoded)
		return nil, fmt.Errorf("GitHub token acquisition failed")
	}
	return encoded, nil
}

func clearLinuxBytes(buffer []byte) {
	for index := range buffer {
		buffer[index] = 0
	}
}
