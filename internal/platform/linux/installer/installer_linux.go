//go:build linux

package installer

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installmetadata"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/runnerpackage"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/runnerregistration"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/sourceversion"
)

const (
	BrokerUnitName = "agent-workstation-gateway-broker.service"
	RunnerUnitName = "agent-workstation-gateway-runner.service"
	BrokerUnitPath = "/etc/systemd/system/" + BrokerUnitName
	RunnerUnitPath = "/etc/systemd/system/" + RunnerUnitName
	ACLBackupName  = "approved-roots.acl"
)

type Input struct {
	Specification      installplan.Spec
	GatewaySourceSHA   string
	BrokerImage        []byte
	ControlImage       []byte
	RunnerImage        *runnerpackage.Image
	RunnerRegistration runnerregistration.Request
	Metadata           installmetadata.Metadata
}

type Error struct{ Rule string }

func (failure *Error) Error() string {
	return fmt.Sprintf("Linux installation transaction failed: %s", failure.Rule)
}

func ValidateReleaseImages(sourceSHA string, brokerImage, controlImage []byte) error {
	if !sourceversion.IsCanonicalGitSHA(sourceSHA) || !validELF(brokerImage, sourceSHA) || !validELF(controlImage, sourceSHA) {
		return installerError("release-image-invalid")
	}
	return nil
}

func Provision(ctx context.Context, input Input) (resultErr error) {
	if ctx == nil || os.Geteuid() != 0 {
		return installerError("root-installer-required")
	}
	if _, err := installplan.Build(input.Specification); err != nil || input.Specification.Platform != "linux" ||
		ValidateReleaseImages(input.GatewaySourceSHA, input.BrokerImage, input.ControlImage) != nil ||
		input.RunnerImage == nil || !input.RunnerImage.PinnedLinuxX64() || installmetadata.Validate(input.Metadata) != nil {
		return installerError("input-invalid")
	}
	if hasUnitUnsafePath(input.Specification) {
		return installerError("systemd-path-unsafe")
	}
	if input.Metadata.InstallationRoot != input.Specification.InstallationRoot || input.Metadata.GatewaySourceSHA != input.GatewaySourceSHA ||
		input.Metadata.ControlRepository != input.RunnerRegistration.Repository.Name() || input.Metadata.RunnerName != input.RunnerRegistration.RunnerName {
		return installerError("metadata-binding-invalid")
	}
	layout, _ := installplan.LinuxLayout(input.Specification.InstallationRoot)
	if preflight(input.Specification, layout) != nil {
		return installerError("preflight-failed")
	}
	createdControlGroup := false
	createdExecutionGroup := false
	createdControlUser := false
	createdExecutionUser := false
	createdRoot := false
	createdRunner := false
	createdProfile := false
	createdTemp := false
	createdUnits := false
	registered := false
	aclApplied := false
	succeeded := false
	defer func() {
		if succeeded {
			return
		}
		rollbackFailed := rollback(context.Background(), input, layout, registered, createdUnits, aclApplied, createdRunner, createdRoot,
			createdProfile, createdTemp, createdControlUser, createdExecutionUser, createdControlGroup, createdExecutionGroup)
		if rollbackFailed {
			rule := "unknown-stage"
			var failure *Error
			if errors.As(resultErr, &failure) {
				rule = failure.Rule
			}
			resultErr = installerError("rollback-failed-after-" + rule)
		}
	}()

	if run(ctx, "groupadd", "--system", input.Specification.ControlAccount) != nil {
		return installerError("control-group-create-failed")
	}
	createdControlGroup = true
	if run(ctx, "groupadd", "--system", input.Specification.ExecutionAccount) != nil {
		return installerError("execution-group-create-failed")
	}
	createdExecutionGroup = true
	if run(ctx, "useradd", "--system", "--gid", input.Specification.ControlAccount, "--home-dir", layout.RunnerRoot,
		"--shell", "/usr/sbin/nologin", "--no-create-home", input.Specification.ControlAccount) != nil {
		return installerError("control-user-create-failed")
	}
	createdControlUser = true
	if run(ctx, "useradd", "--system", "--gid", input.Specification.ExecutionAccount, "--home-dir", input.Specification.ProfileRoot,
		"--shell", "/usr/sbin/nologin", "--no-create-home", input.Specification.ExecutionAccount) != nil {
		return installerError("execution-user-create-failed")
	}
	createdExecutionUser = true
	controlUID, controlGID, err := lookupIDs(input.Specification.ControlAccount)
	if err != nil {
		return installerError("control-identity-query-failed")
	}
	executionUID, executionGID, err := lookupIDs(input.Specification.ExecutionAccount)
	if err != nil || controlUID == executionUID || controlGID == executionGID {
		return installerError("execution-identity-query-failed")
	}
	binding := installplan.IdentityBinding{
		ControlIdentifier: "uid:" + strconv.Itoa(controlUID), ControlPrimaryGroupIdentifier: "gid:" + strconv.Itoa(controlGID),
		ExecutionIdentifier: "uid:" + strconv.Itoa(executionUID), ExecutionPrimaryGroupIdentifier: "gid:" + strconv.Itoa(executionGID),
	}
	configuration, err := installplan.Bind(input.Specification, binding)
	if err != nil {
		return installerError("identity-binding-invalid")
	}
	if err := createDirectory(layout.Root, 0o750, 0, 0); err != nil {
		return installerError("installation-root-create-failed")
	}
	createdRoot = true
	for _, item := range []struct {
		path string
		mode fs.FileMode
	}{{layout.BinDirectory, 0o755}, {layout.StateDirectory, 0o700}} {
		if err := createDirectory(item.path, item.mode, 0, 0); err != nil {
			return installerError("protected-directory-create-failed")
		}
	}
	if err := writeNew(layout.BrokerExecutable, input.BrokerImage, 0o755, 0, 0); err != nil ||
		writeNew(layout.ControlExecutable, input.ControlImage, 0o755, 0, 0) != nil {
		return installerError("release-image-write-failed")
	}
	configurationBytes, err := installconfig.MarshalCanonical(configuration)
	if err != nil || writeNew(layout.InstallationConfig, configurationBytes, 0o600, 0, 0) != nil {
		return installerError("configuration-write-failed")
	}
	metadataBytes, err := installmetadata.MarshalCanonical(input.Metadata)
	if err != nil || writeNew(layout.InstallationMetadata, metadataBytes, 0o600, 0, 0) != nil {
		return installerError("metadata-write-failed")
	}
	backup, err := captureACL(ctx, input.Specification.ApprovedRoots)
	if err != nil || writeNew(filepath.Join(layout.StateDirectory, ACLBackupName), backup, 0o600, 0, 0) != nil {
		return installerError("acl-backup-failed")
	}
	if applyACL(ctx, input.Specification.ExecutionAccount, input.Specification.ApprovedRoots) != nil {
		return installerError("approved-root-acl-failed")
	}
	aclApplied = true
	if err := createDirectory(input.Specification.ProfileRoot, 0o700, executionUID, executionGID); err != nil {
		return installerError("profile-root-create-failed")
	}
	createdProfile = true
	if err := createDirectory(input.Specification.TempRoot, 0o700, executionUID, executionGID); err != nil {
		return installerError("temp-root-create-failed")
	}
	createdTemp = true
	if err := createDirectory(layout.RunnerRoot, 0o700, controlUID, controlGID); err != nil {
		return installerError("runner-root-create-failed")
	}
	createdRunner = true
	store := &runnerStore{root: layout.RunnerRoot, uid: controlUID, gid: controlGID}
	if err := input.RunnerImage.Extract(ctx, store); err != nil {
		return installerError("runner-extract-failed")
	}
	if validateRunnerRuntime(ctx, layout, controlUID, controlGID) != nil {
		return installerError("runner-runtime-unavailable")
	}
	for _, directory := range []string{layout.RunnerWorkDirectory, layout.RunnerResponseDirectory, filepath.Dir(layout.RunnerControlExecutable)} {
		if err := createDirectory(directory, 0o700, controlUID, controlGID); err != nil {
			return installerError("runner-state-create-failed")
		}
	}
	if err := writeNew(layout.RunnerControlExecutable, input.ControlImage, 0o700, controlUID, controlGID); err != nil {
		return installerError("runner-control-write-failed")
	}
	if err := configureRunner(ctx, layout, input.RunnerRegistration, controlUID, controlGID); err != nil {
		return installerError("runner-registration-failed")
	}
	registered = true
	if err := sealRunner(layout.RunnerRoot, controlUID, controlGID); err != nil {
		return installerError("runner-state-seal-failed")
	}
	brokerUnit := ExpectedBrokerUnit(layout, input.Specification)
	runnerUnit := ExpectedRunnerUnit(layout, input.Specification.ControlAccount)
	if writeNew(BrokerUnitPath, []byte(brokerUnit), 0o644, 0, 0) != nil {
		return installerError("systemd-unit-write-failed")
	}
	createdUnits = true
	if writeNew(RunnerUnitPath, []byte(runnerUnit), 0o644, 0, 0) != nil {
		return installerError("systemd-unit-write-failed")
	}
	if run(ctx, "systemctl", "daemon-reload") != nil || run(ctx, "systemctl", "enable", BrokerUnitName, RunnerUnitName) != nil ||
		run(ctx, "systemctl", "start", BrokerUnitName) != nil || run(ctx, "systemctl", "start", RunnerUnitName) != nil {
		return installerError("service-start-failed")
	}
	succeeded = true
	return nil
}

type runnerStore struct {
	root     string
	uid, gid int
}

func (store *runnerStore) CreateDirectory(relative string) error {
	path, err := store.path(relative)
	if err != nil {
		return err
	}
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return os.Chown(path, store.uid, store.gid)
}

func (store *runnerStore) CreateFile(relative string) (io.WriteCloser, error) {
	return store.CreateFileMode(relative, 0o600)
}

func (store *runnerStore) CreateFileMode(relative string, mode fs.FileMode) (io.WriteCloser, error) {
	path, err := store.path(relative)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode.Perm())
	if err != nil {
		return nil, err
	}
	if err := file.Chown(store.uid, store.gid); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return file, nil
}

func (store *runnerStore) CreateSymlink(relative, target string) error {
	path, err := store.path(relative)
	if err != nil || filepath.IsAbs(target) || filepath.Clean(target) != target {
		return installerError("runner-link-invalid")
	}
	resolved := filepath.Clean(filepath.Join(filepath.Dir(path), filepath.FromSlash(target)))
	if resolved == store.root || !strings.HasPrefix(resolved, store.root+string(os.PathSeparator)) {
		return installerError("runner-link-escape")
	}
	if err := os.Symlink(target, path); err != nil {
		return err
	}
	return os.Lchown(path, store.uid, store.gid)
}

func (store *runnerStore) path(relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative {
		return "", installerError("runner-path-invalid")
	}
	path := filepath.Join(store.root, filepath.FromSlash(relative))
	if path != store.root && !strings.HasPrefix(path, store.root+string(os.PathSeparator)) {
		return "", installerError("runner-path-escape")
	}
	return path, nil
}

func preflight(specification installplan.Spec, layout installplan.Layout) error {
	for _, path := range []string{layout.Root, layout.RunnerRoot, specification.ProfileRoot, specification.TempRoot, BrokerUnitPath, RunnerUnitPath} {
		if exists(path) {
			return installerError("owned-object-exists")
		}
	}
	for _, name := range []string{specification.ControlAccount, specification.ExecutionAccount} {
		if _, err := user.Lookup(name); err == nil {
			return installerError("account-exists")
		}
		if _, err := user.LookupGroup(name); err == nil {
			return installerError("group-exists")
		}
	}
	for _, root := range specification.ApprovedRoots {
		resolved, err := filepath.EvalSymlinks(root)
		info, statErr := os.Lstat(root)
		if err != nil || statErr != nil || resolved != root || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return installerError("approved-root-invalid")
		}
	}
	for _, command := range []string{"groupadd", "useradd", "userdel", "groupdel", "getfacl", "setfacl", "systemctl", "/bin/bash"} {
		if _, err := exec.LookPath(command); err != nil {
			return installerError("dependency-unavailable")
		}
	}
	return nil
}

func configureRunner(ctx context.Context, layout installplan.Layout, request runnerregistration.Request, uid, gid int) error {
	if request.Repository.Name() == "" || len(request.RegistrationToken) < runnerregistration.MinTokenBytes {
		return installerError("runner-registration-invalid")
	}
	script := filepath.Join(layout.RunnerRoot, "config.sh")
	arguments := []string{script, "--unattended", "--url", "https://github.com/" + request.Repository.Name(), "--name", request.RunnerName,
		"--work", layout.RunnerWorkDirectory, "--disableupdate", "--no-default-labels", "--labels", runnerregistration.RegistrationLabel}
	command := exec.CommandContext(ctx, "/bin/bash", arguments...)
	command.Dir = layout.RunnerRoot
	command.Env = []string{
		"ACTIONS_RUNNER_INPUT_TOKEN=" + string(request.RegistrationToken), "HOME=" + layout.RunnerRoot,
		"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8",
	}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}, Setpgid: true, Pdeathsig: syscall.SIGKILL}
	output := &boundedOutput{maximum: 1024 * 1024}
	command.Stdout, command.Stderr = output, output
	if err := command.Run(); err != nil {
		return installerError("runner-configure-failed")
	}
	return nil
}

type boundedOutput struct {
	written int
	maximum int
}

func (output *boundedOutput) Write(content []byte) (int, error) {
	output.written += len(content)
	if output.written > output.maximum {
		return 0, installerError("process-output-limit")
	}
	return len(content), nil
}

func sealRunner(root string, uid, gid int) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return installerError("runner-object-invalid")
		}
		if entry.Type()&os.ModeSymlink != 0 {
			target, readErr := os.Readlink(path)
			resolved := filepath.Clean(filepath.Join(filepath.Dir(path), target))
			if readErr != nil || filepath.IsAbs(target) || (resolved != root && !strings.HasPrefix(resolved, root+string(os.PathSeparator))) || os.Lchown(path, uid, gid) != nil {
				return installerError("runner-link-invalid")
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		mode := fs.FileMode(0o600)
		if info.IsDir() {
			mode = 0o700
		} else if info.Mode().Perm()&0o111 != 0 {
			mode = 0o700
		}
		if err := os.Chown(path, uid, gid); err != nil || os.Chmod(path, mode) != nil {
			return installerError("runner-object-seal-failed")
		}
		return nil
	})
}

func captureACL(ctx context.Context, roots []string) ([]byte, error) {
	command := exec.CommandContext(ctx, "getfacl", append([]string{"--absolute-names"}, roots...)...)
	output, err := command.Output()
	if err != nil || len(output) == 0 || len(output) > 4*1024*1024 {
		return nil, installerError("acl-capture-failed")
	}
	return output, nil
}

func applyACL(ctx context.Context, account string, roots []string) error {
	for _, root := range roots {
		if run(ctx, "setfacl", "--modify", "u:"+account+":rwx", "--modify", "d:u:"+account+":rwx", root) != nil {
			return installerError("acl-apply-failed")
		}
	}
	return nil
}

func restoreACL(ctx context.Context, layout installplan.Layout) error {
	backup, err := os.Open(filepath.Join(layout.StateDirectory, ACLBackupName))
	if err != nil {
		return err
	}
	defer backup.Close()
	command := exec.CommandContext(ctx, "setfacl", "--restore=-")
	command.Stdin = backup
	command.Stdout, command.Stderr = io.Discard, io.Discard
	return command.Run()
}

func ExpectedBrokerUnit(layout installplan.Layout, specification installplan.Spec) string {
	readWrite := append([]string{"/run/agent-workstation-gateway", specification.ProfileRoot, specification.TempRoot}, specification.ApprovedRoots...)
	return "[Unit]\nDescription=Agent Workstation Gateway broker\nAfter=network.target\n\n[Service]\nType=simple\n" +
		"ExecStart=" + layout.BrokerExecutable + " --installation-root " + layout.Root + "\nUser=root\nGroup=root\n" +
		"NoNewPrivileges=true\nPrivateTmp=false\nProtectSystem=strict\nProtectKernelTunables=true\nProtectKernelModules=true\n" +
		"ProtectControlGroups=true\nRestrictSUIDSGID=false\nRuntimeDirectory=agent-workstation-gateway\nRuntimeDirectoryMode=0750\nCapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_KILL CAP_CHOWN\n" +
		"ReadWritePaths=" + strings.Join(readWrite, " ") + "\nRestart=on-failure\nRestartSec=2s\nTimeoutStopSec=30s\n\n[Install]\nWantedBy=multi-user.target\n"
}

func ExpectedRunnerUnit(layout installplan.Layout, account string) string {
	return "[Unit]\nDescription=Agent Workstation Gateway control runner\nAfter=network-online.target " + BrokerUnitName + "\nWants=network-online.target\nRequires=" + BrokerUnitName + "\n\n[Service]\nType=simple\n" +
		"User=" + account + "\nGroup=" + account + "\nWorkingDirectory=" + layout.RunnerRoot + "\n" +
		"Environment=HOME=" + layout.RunnerRoot + "\nEnvironment=DOTNET_EnableDiagnostics=0\nExecStart=" + filepath.Join(layout.RunnerRoot, "run.sh") + "\n" +
		"NoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nReadWritePaths=" + layout.RunnerRoot + "\nRestrictSUIDSGID=false\nRestart=on-failure\nRestartSec=5s\nTimeoutStopSec=30s\n\n[Install]\nWantedBy=multi-user.target\n"
}

func rollback(ctx context.Context, input Input, layout installplan.Layout, registered, units, acl, runner, root, profile, temp, controlUser, executionUser, controlGroup, executionGroup bool) bool {
	failed := false
	if units {
		failed = run(ctx, "systemctl", "disable", "--now", RunnerUnitName, BrokerUnitName) != nil || failed
		failed = removeFile(RunnerUnitPath) != nil || failed
		failed = removeFile(BrokerUnitPath) != nil || failed
		failed = run(ctx, "systemctl", "daemon-reload") != nil || failed
	}
	if registered && len(input.RunnerRegistration.RemovalToken) >= runnerregistration.MinTokenBytes {
		_ = removeLocalRunner(ctx, layout, input.Specification.ControlAccount, input.RunnerRegistration.RemovalToken)
	}
	if acl {
		failed = restoreACL(ctx, layout) != nil || failed
	}
	if runner {
		failed = os.RemoveAll(layout.RunnerRoot) != nil || failed
	}
	if profile {
		failed = os.Remove(input.Specification.ProfileRoot) != nil || failed
	}
	if temp {
		failed = os.Remove(input.Specification.TempRoot) != nil || failed
	}
	if root {
		failed = os.RemoveAll(layout.Root) != nil || failed
	}
	if executionUser {
		failed = run(ctx, "userdel", input.Specification.ExecutionAccount) != nil || failed
	}
	if controlUser {
		failed = run(ctx, "userdel", input.Specification.ControlAccount) != nil || failed
	}
	if executionGroup {
		failed = deleteGroup(ctx, input.Specification.ExecutionAccount) != nil || failed
	}
	if controlGroup {
		failed = deleteGroup(ctx, input.Specification.ControlAccount) != nil || failed
	}
	return failed
}

func removeLocalRunner(ctx context.Context, layout installplan.Layout, account string, token []byte) error {
	uid, gid, err := lookupIDs(account)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "/bin/bash", filepath.Join(layout.RunnerRoot, "config.sh"), "remove")
	command.Dir = layout.RunnerRoot
	command.Env = []string{"ACTIONS_RUNNER_INPUT_TOKEN=" + string(token), "HOME=" + layout.RunnerRoot, "PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8"}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}, Setpgid: true, Pdeathsig: syscall.SIGKILL}
	command.Stdout, command.Stderr = io.Discard, io.Discard
	return command.Run()
}

func validateRunnerRuntime(ctx context.Context, layout installplan.Layout, uid, gid int) error {
	command := exec.CommandContext(ctx, filepath.Join(layout.RunnerRoot, "bin", "Runner.Listener"), "--version")
	command.Dir = layout.RunnerRoot
	command.Env = []string{"HOME=" + layout.RunnerRoot, "PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8"}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}, Setpgid: true, Pdeathsig: syscall.SIGKILL}
	command.Stdout, command.Stderr = io.Discard, io.Discard
	return command.Run()
}

func deleteGroup(ctx context.Context, name string) error {
	if err := run(ctx, "groupdel", name); err != nil {
		if _, lookupErr := user.LookupGroup(name); lookupErr == nil {
			return err
		}
	}
	return nil
}

func createDirectory(path string, mode fs.FileMode, uid, gid int) error {
	if err := os.Mkdir(path, mode); err != nil {
		return err
	}
	if err := os.Chown(path, uid, gid); err != nil || os.Chmod(path, mode) != nil {
		return installerError("directory-policy-failed")
	}
	return nil
}

func writeNew(path string, content []byte, mode fs.FileMode, uid, gid int) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if err := file.Chown(uid, gid); err != nil {
		_ = file.Close()
		return err
	}
	if err := writeAll(file, content); err != nil || file.Sync() != nil || file.Close() != nil {
		return installerError("file-write-failed")
	}
	return nil
}

func lookupIDs(name string) (int, int, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return 0, 0, err
	}
	uid, uidErr := strconv.Atoi(account.Uid)
	gid, gidErr := strconv.Atoi(account.Gid)
	if uidErr != nil || gidErr != nil || uid <= 0 || gid <= 0 {
		return 0, 0, installerError("identity-invalid")
	}
	return uid, gid, nil
}

func run(ctx context.Context, executable string, args ...string) error {
	command := exec.CommandContext(ctx, executable, args...)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	return command.Run()
}

func validELF(image []byte, sourceSHA string) bool {
	if len(image) == 0 || len(image) > 128*1024*1024 || !bytes.Contains(image, []byte(sourceSHA)) {
		return false
	}
	file, err := elf.NewFile(bytes.NewReader(image))
	if err != nil {
		return false
	}
	defer file.Close()
	expected := elf.EM_X86_64
	if runtime.GOARCH == "arm64" {
		expected = elf.EM_AARCH64
	}
	return file.FileHeader.Class == elf.ELFCLASS64 && file.FileHeader.Machine == expected && file.Type == elf.ET_EXEC
}

func hasUnitUnsafePath(specification installplan.Spec) bool {
	paths := []string{specification.InstallationRoot, specification.ProfileRoot, specification.TempRoot}
	paths = append(paths, specification.ApprovedRoots...)
	for _, path := range paths {
		if strings.ContainsAny(path, " \t\r\n\"'\\") {
			return true
		}
	}
	return false
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil || !errors.Is(err, os.ErrNotExist)
}

func writeAll(writer io.Writer, content []byte) error {
	for len(content) > 0 {
		count, err := writer.Write(content)
		if count <= 0 || count > len(content) {
			return io.ErrShortWrite
		}
		content = content[count:]
		if err != nil {
			return err
		}
	}
	return nil
}

func removeFile(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func installerError(rule string) error { return &Error{Rule: rule} }
