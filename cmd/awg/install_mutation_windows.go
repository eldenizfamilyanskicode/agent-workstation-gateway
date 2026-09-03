//go:build windows

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
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/installer"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/protectedstate"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/servicectl"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/runnerpackage"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/runnerregistration"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/sourceversion"
	controltemplate "github.com/eldenizfamilyanskicode/agent-workstation-gateway/templates/control-repository"
)

const maxGitHubTokenOutput = 4096

type installGitHub interface {
	CreatePersonalPrivate(context.Context) error
	VerifyExclusivePrivate(context.Context) error
	EnsureControlFile(context.Context, string, []byte) (bool, error)
	RegistrationToken(context.Context) ([]byte, error)
	RemovalToken(context.Context) ([]byte, error)
	Close()
}

type installLease interface {
	Commit() error
	Close() error
}

type installDependencies struct {
	githubToken    func(context.Context) ([]byte, error)
	github         func([]byte, string) (installGitHub, error)
	render         func(controltemplate.Config) ([]controltemplate.RenderedFile, error)
	inspect        func([]byte) (*runnerpackage.Image, error)
	validateImages func(string, []byte, []byte) error
	provision      func(context.Context, installer.Input) (installLease, error)
	start          func(context.Context) error
}

func runInstallMutation(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, sourceSHA string) int {
	return runInstallMutationWithDependencies(ctx, args, stdout, stderr, sourceSHA, installDependencies{
		githubToken: acquireGitHubToken,
		github: func(token []byte, repository string) (installGitHub, error) {
			return githubcontrol.New(token, repository)
		},
		render:         controltemplate.Render,
		inspect:        runnerpackage.InspectPinnedWindowsX64,
		validateImages: installer.ValidateReleaseImages,
		provision: func(ctx context.Context, input installer.Input) (installLease, error) {
			return installer.Provision(ctx, input)
		},
		start: servicectl.Start,
	})
}

func runInstallMutationWithDependencies(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	sourceSHA string,
	deps installDependencies,
) int {
	flags := flag.NewFlagSet("awg install", flag.ContinueOnError)
	flags.SetOutput(stderr)
	specPath := flags.String("spec", "", "path to a Windows install specification")
	repositoryName := flags.String("repository", "", "dedicated personal private control repository")
	createRepository := flags.Bool("create-repository", false, "create and initialize the private control repository")
	brokerPath := flags.String("broker-image", "", "pinned awg-broker.exe release image")
	controlPath := flags.String("control-image", "", "pinned awg.exe release image")
	runnerPath := flags.String("runner-archive", "", "pinned official Windows x64 runner archive")
	hostedControlURL := flags.String("hosted-control-url", "", "pinned awg-control Linux x64 release URL")
	hostedControlDigest := flags.String("hosted-control-sha256", "", "pinned awg-control Linux x64 SHA-256")
	runnerName := flags.String("runner-name", "awg-windows-x64", "dedicated runner name")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *specPath == "" || *repositoryName == "" ||
		*brokerPath == "" || *controlPath == "" || *runnerPath == "" || *hostedControlURL == "" ||
		*hostedControlDigest == "" || *runnerName == "" {
		fmt.Fprintln(stderr, "install requires the specification, private repository, pinned release images, and hosted control digest")
		return 2
	}
	if ctx == nil || stdout == nil || stderr == nil || !sourceversion.IsCanonicalGitSHA(sourceSHA) ||
		deps.githubToken == nil || deps.github == nil || deps.render == nil || deps.inspect == nil || deps.validateImages == nil || deps.provision == nil || deps.start == nil {
		fmt.Fprintln(stderr, "trusted installation inputs are unavailable")
		return 1
	}
	specificationBytes, err := readBounded(*specPath, installplan.MaxSpecBytes)
	if err != nil {
		fmt.Fprintln(stderr, "could not read bounded install specification")
		return 1
	}
	specification, err := installplan.Decode(specificationBytes)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	brokerImage, brokerErr := readBounded(*brokerPath, protectedstate.MaxProtectedExecutableBytes)
	controlImage, controlErr := readBounded(*controlPath, protectedstate.MaxProtectedExecutableBytes)
	runnerArchive, runnerErr := readBounded(*runnerPath, runnerpackage.MaxArchiveBytes)
	if brokerErr != nil || controlErr != nil || runnerErr != nil {
		fmt.Fprintln(stderr, "could not read bounded release input")
		return 1
	}
	if err := deps.validateImages(sourceSHA, brokerImage, controlImage); err != nil {
		fmt.Fprintln(stderr, "release image verification failed")
		return 1
	}
	runnerImage, err := deps.inspect(runnerArchive)
	if err != nil || runnerImage == nil {
		fmt.Fprintln(stderr, "runner archive verification failed")
		return 1
	}
	rendered, err := deps.render(controltemplate.Config{
		GatewaySourceSHA: sourceSHA, ControlBinaryURL: *hostedControlURL,
		ControlBinarySHA256: *hostedControlDigest, InstallationRoot: specification.InstallationRoot,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	token, err := deps.githubToken(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "authenticated GitHub CLI session is unavailable")
		return 1
	}
	defer clearBytes(token)
	github, err := deps.github(token, *repositoryName)
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
		controlFiles = append(controlFiles, installmetadata.ControlFile{
			Path: file.Path, SHA256: hex.EncodeToString(digest[:]), Owned: created,
		})
	}
	registrationToken, err := github.RegistrationToken(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "runner registration token is unavailable")
		return 1
	}
	defer clearBytes(registrationToken)
	removalToken, err := github.RemovalToken(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "runner removal token is unavailable")
		return 1
	}
	defer clearBytes(removalToken)
	repository, err := runnerregistration.VerifyPrivateRepository(*repositoryName, true)
	if err != nil {
		fmt.Fprintln(stderr, "private repository binding failed")
		return 1
	}
	lease, err := deps.provision(ctx, installer.Input{
		Specification: specification, GatewaySourceSHA: sourceSHA,
		BrokerImage: brokerImage, ControlImage: controlImage, RunnerImage: runnerImage,
		RunnerRegistration: runnerregistration.Request{
			Repository: repository, RunnerName: *runnerName,
			RegistrationToken: registrationToken, RemovalToken: removalToken,
		},
		Metadata: installmetadata.Metadata{
			MetadataVersion: installmetadata.Version, Platform: specification.Platform,
			InstallationRoot: specification.InstallationRoot, ControlRepository: *repositoryName,
			RunnerName: *runnerName, GatewaySourceSHA: sourceSHA, ControlFiles: controlFiles,
		},
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if lease == nil {
		fmt.Fprintln(stderr, "Windows installation transaction failed")
		return 1
	}
	defer lease.Close()
	if err := lease.Commit(); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := deps.start(ctx); err != nil {
		fmt.Fprintln(stderr, "gateway installed but fixed services failed to start")
		return 1
	}
	fmt.Fprintln(stdout, "gateway installed")
	return 0
}

func acquireGitHubToken(ctx context.Context) ([]byte, error) {
	command := exec.CommandContext(ctx, "gh", "auth", "token", "--hostname", "github.com")
	command.Stderr = io.Discard
	pipe, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, err
	}
	encoded, readErr := io.ReadAll(io.LimitReader(pipe, maxGitHubTokenOutput+1))
	waitErr := command.Wait()
	encoded = bytes.TrimSpace(encoded)
	if readErr != nil || waitErr != nil || len(encoded) < 16 || len(encoded) > maxGitHubTokenOutput || bytes.ContainsAny(encoded, "\x00\r\n\t ") {
		clearBytes(encoded)
		return nil, fmt.Errorf("GitHub token acquisition failed")
	}
	return encoded, nil
}

func clearBytes(buffer []byte) {
	for index := range buffer {
		buffer[index] = 0
	}
}
