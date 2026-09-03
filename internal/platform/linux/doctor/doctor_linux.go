//go:build linux

package doctor

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installmetadata"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/linux/brokeripc"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/linux/installer"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/sourceversion"
)

type Report struct {
	ProtectedState            bool `json:"protected_state"`
	Identities                bool `json:"identities"`
	FilesystemPolicy          bool `json:"filesystem_policy"`
	RunnerState               bool `json:"runner_state"`
	ServicePolicy             bool `json:"service_policy"`
	ServicesRunning           bool `json:"services_running"`
	PrivateRepository         bool `json:"private_repository"`
	ExclusiveReaders          bool `json:"exclusive_readers"`
	ExecutionCredentialDenied bool `json:"execution_credential_acl_denies"`
	RunnerCredentialsDenied   bool `json:"runner_credentials_acl_denies"`
}

type Installation struct {
	Configuration installconfig.Config
	Metadata      installmetadata.Metadata
}

type Error struct{ Rule string }

func (failure *Error) Error() string { return fmt.Sprintf("Linux doctor failed: %s", failure.Rule) }

func CheckLocal(ctx context.Context, installationRoot, sourceSHA string) (Report, Installation, error) {
	report, installation, err := InspectInstalled(ctx, installationRoot, sourceSHA)
	if err != nil {
		return Report{}, Installation{}, err
	}
	if run(ctx, "systemctl", "is-active", "--quiet", installer.BrokerUnitName) != nil ||
		run(ctx, "systemctl", "is-active", "--quiet", installer.RunnerUnitName) != nil {
		return Report{}, Installation{}, doctorError("services-not-running")
	}
	if verifySocket(installation.Configuration) != nil {
		return Report{}, Installation{}, doctorError("socket-policy-invalid")
	}
	report.ServicesRunning = true
	return report, installation, nil
}

func InspectInstalled(ctx context.Context, installationRoot, sourceSHA string) (Report, Installation, error) {
	if ctx == nil || os.Geteuid() != 0 || !sourceversion.IsCanonicalGitSHA(sourceSHA) {
		return Report{}, Installation{}, doctorError("input-invalid")
	}
	layout, err := installplan.LinuxLayout(installationRoot)
	if err != nil {
		return Report{}, Installation{}, doctorError("installation-root-invalid")
	}
	for _, item := range []struct {
		path       string
		directory  bool
		mode       os.FileMode
		maximum    int64
		executable bool
	}{
		{layout.Root, true, 0o750, 0, false}, {layout.BinDirectory, true, 0o755, 0, false}, {layout.StateDirectory, true, 0o700, 0, false},
		{layout.BrokerExecutable, false, 0o755, 128 * 1024 * 1024, true}, {layout.ControlExecutable, false, 0o755, 128 * 1024 * 1024, true},
		{layout.InstallationConfig, false, 0o600, installconfig.MaxConfigBytes, false},
		{layout.InstallationMetadata, false, 0o600, installmetadata.MaxBytes, false},
		{filepath.Join(layout.StateDirectory, installer.ACLBackupName), false, 0o600, 4 * 1024 * 1024, false},
	} {
		if verifyObject(item.path, item.directory, item.mode, 0, 0, item.maximum) != nil {
			return Report{}, Installation{}, doctorError("protected-state-invalid")
		}
	}
	configurationBytes, err := os.ReadFile(layout.InstallationConfig)
	if err != nil {
		return Report{}, Installation{}, doctorError("configuration-read-failed")
	}
	configuration, err := installconfig.Decode(configurationBytes)
	clear(configurationBytes)
	if err != nil || configuration.Platform != platformpath.Linux {
		return Report{}, Installation{}, doctorError("configuration-invalid")
	}
	metadataBytes, err := os.ReadFile(layout.InstallationMetadata)
	if err != nil {
		return Report{}, Installation{}, doctorError("metadata-read-failed")
	}
	metadata, err := installmetadata.Decode(metadataBytes)
	clear(metadataBytes)
	if err != nil || metadata.InstallationRoot != installationRoot || metadata.GatewaySourceSHA != sourceSHA || metadata.Platform != platformpath.Linux {
		return Report{}, Installation{}, doctorError("metadata-invalid")
	}
	controlUID, controlGID, err := verifyIdentity(configuration.ControlIdentity)
	if err != nil {
		return Report{}, Installation{}, doctorError("control-identity-invalid")
	}
	executionUID, executionGID, err := verifyIdentity(configuration.ExecutionIdentity)
	if err != nil || controlUID == executionUID || controlGID == executionGID {
		return Report{}, Installation{}, doctorError("execution-identity-invalid")
	}
	if verifyObject(configuration.ProfileRoot, true, 0o700, executionUID, executionGID, 0) != nil ||
		verifyObject(configuration.TempRoot, true, 0o700, executionUID, executionGID, 0) != nil || verifyApprovedRoots(ctx, configuration) != nil {
		return Report{}, Installation{}, doctorError("filesystem-policy-invalid")
	}
	if verifyObject(layout.RunnerRoot, true, 0o700, controlUID, controlGID, 0) != nil ||
		verifyObject(layout.RunnerControlExecutable, false, 0o700, controlUID, controlGID, 128*1024*1024) != nil {
		return Report{}, Installation{}, doctorError("runner-state-invalid")
	}
	for _, credential := range []string{".credentials", ".credentials_rsaparams", ".runner"} {
		if verifyObject(filepath.Join(layout.RunnerRoot, credential), false, 0o600, controlUID, controlGID, 4*1024*1024) != nil {
			return Report{}, Installation{}, doctorError("runner-credential-invalid")
		}
	}
	if canReadAs(executionUID, executionGID, layout.InstallationConfig) || canReadAs(executionUID, executionGID, filepath.Join(layout.RunnerRoot, ".credentials")) {
		return Report{}, Installation{}, doctorError("execution-read-boundary-invalid")
	}
	specification := installplan.Spec{
		ConfigVersion: configuration.ConfigVersion, Platform: configuration.Platform, InstallationRoot: installationRoot,
		ControlAccount: configuration.ControlIdentity.Name, ExecutionAccount: configuration.ExecutionIdentity.Name,
		ApprovedRoots: configuration.ApprovedRoots, Shells: configuration.Shells, ProfileRoot: configuration.ProfileRoot,
		TempRoot: configuration.TempRoot, PathEntries: configuration.PathEntries, Capabilities: configuration.Capabilities,
	}
	if verifyUnit(installer.BrokerUnitPath, installer.ExpectedBrokerUnit(layout, specification)) != nil ||
		verifyUnit(installer.RunnerUnitPath, installer.ExpectedRunnerUnit(layout, configuration.ControlIdentity.Name)) != nil ||
		verifyEffectiveService(ctx, configuration.ControlIdentity.Name) != nil {
		return Report{}, Installation{}, doctorError("service-policy-invalid")
	}
	return Report{ProtectedState: true, Identities: true, FilesystemPolicy: true, RunnerState: true, ServicePolicy: true,
		ExecutionCredentialDenied: true, RunnerCredentialsDenied: true}, Installation{Configuration: configuration, Metadata: metadata}, nil
}

func verifyIdentity(principal installconfig.Principal) (int, int, error) {
	account, err := user.Lookup(principal.Name)
	if err != nil {
		return 0, 0, err
	}
	uid, uidErr := strconv.Atoi(account.Uid)
	gid, gidErr := strconv.Atoi(account.Gid)
	groups, groupsErr := account.GroupIds()
	if uidErr != nil || gidErr != nil || groupsErr != nil || uid <= 0 || gid <= 0 || principal.Identifier != "uid:"+strconv.Itoa(uid) ||
		principal.PrimaryGroupIdentifier != "gid:"+strconv.Itoa(gid) || len(groups) != 1 || groups[0] != account.Gid {
		return 0, 0, doctorError("identity-mismatch")
	}
	return uid, gid, nil
}

func verifyApprovedRoots(ctx context.Context, configuration installconfig.Config) error {
	for _, root := range configuration.ApprovedRoots {
		resolved, err := filepath.EvalSymlinks(root)
		if err != nil || resolved != root {
			return doctorError("approved-root-invalid")
		}
		command := exec.CommandContext(ctx, "getfacl", "--absolute-names", "--omit-header", root)
		output, err := command.Output()
		if err != nil || len(output) > 1024*1024 {
			return doctorError("approved-root-acl-unavailable")
		}
		body := string(output)
		if !strings.Contains(body, "user:"+configuration.ExecutionIdentity.Name+":rwx") ||
			!strings.Contains(body, "default:user:"+configuration.ExecutionIdentity.Name+":rwx") {
			return doctorError("approved-root-acl-mismatch")
		}
	}
	return nil
}

func verifyObject(path string, directory bool, mode os.FileMode, uid, gid int, maximum int64) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory || info.Mode().Perm() != mode.Perm() {
		return doctorError("object-shape-invalid")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != uid || int(stat.Gid) != gid || (!directory && (info.Size() <= 0 || info.Size() > maximum)) {
		return doctorError("object-policy-invalid")
	}
	return nil
}

func verifyUnit(path, expected string) error {
	encoded, err := os.ReadFile(path)
	if err != nil || string(encoded) != expected {
		return doctorError("unit-content-invalid")
	}
	return verifyObject(path, false, 0o644, 0, 0, 64*1024)
}

func verifyEffectiveService(ctx context.Context, controlAccount string) error {
	for _, item := range []struct {
		unit, expected string
	}{
		{installer.BrokerUnitName, "User=root\nGroup=root\nNoNewPrivileges=yes\nPrivateTmp=no\nProtectSystem=strict\nRestrictSUIDSGID=no"},
		{installer.RunnerUnitName, "User=" + controlAccount + "\nGroup=" + controlAccount + "\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nRestrictSUIDSGID=no"},
	} {
		command := exec.CommandContext(ctx, "systemctl", "show", item.unit, "--property=User,Group,NoNewPrivileges,PrivateTmp,ProtectSystem,RestrictSUIDSGID")
		output, err := command.Output()
		if err != nil {
			return doctorError("unit-effective-policy-unavailable")
		}
		body := strings.TrimSpace(string(output))
		for _, line := range strings.Split(item.expected, "\n") {
			if !strings.Contains(body, line) {
				return doctorError("unit-effective-policy-mismatch")
			}
		}
	}
	return nil
}

func verifySocket(configuration installconfig.Config) error {
	info, err := os.Lstat(brokeripc.SocketPath)
	if err != nil {
		return doctorError("socket-unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	expectedGID, _ := strconv.Atoi(strings.TrimPrefix(configuration.ControlIdentity.PrimaryGroupIdentifier, "gid:"))
	if !ok || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o660 || stat.Uid != 0 || int(stat.Gid) != expectedGID {
		return doctorError("socket-mismatch")
	}
	return nil
}

func canReadAs(uid, gid int, path string) bool {
	command := exec.Command("/usr/bin/test", "-r", path)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}}
	return command.Run() == nil
}

func run(ctx context.Context, executable string, args ...string) error {
	command := exec.CommandContext(ctx, executable, args...)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	return command.Run()
}

func clear(content []byte) {
	for index := range content {
		content[index] = 0
	}
}

func doctorError(rule string) error { return &Error{Rule: rule} }
