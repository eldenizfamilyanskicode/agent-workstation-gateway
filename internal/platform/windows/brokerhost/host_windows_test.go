//go:build windows

package brokerhost

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/brokersession"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/process"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

const syntheticSourceSHA = "0123456789abcdef0123456789abcdef01234567"

type fakeListener struct {
	connection connection
	acceptErr  error
	closeErr   error
	accepts    int
	closes     int
}

func (listener *fakeListener) Accept(context.Context) (connection, error) {
	listener.accepts++
	return listener.connection, listener.acceptErr
}

func (listener *fakeListener) Close() error {
	listener.closes++
	return listener.closeErr
}

type fakeConnection struct {
	closeErr error
	closes   int
}

func (*fakeConnection) ReadContext(context.Context, []byte) (int, error)  { return 0, nil }
func (*fakeConnection) WriteContext(context.Context, []byte) (int, error) { return 0, nil }
func (connection *fakeConnection) Close() error {
	connection.closes++
	return connection.closeErr
}

type fakeHandler struct {
	err     error
	handles int
}

func (handler *fakeHandler) Handle(context.Context, brokersession.ContextTransport) error {
	handler.handles++
	return handler.err
}

func TestNewRuntimeDerivesStateAndComposesRealExecutionDependencies(t *testing.T) {
	configuration := validWindowsConfiguration()
	encoded, err := installconfig.MarshalCanonical(configuration)
	if err != nil {
		t.Fatal(err)
	}
	var returnedBuffer []byte
	var readPath string
	var readMaximum int
	var credentialPath string
	var credentialMaximum int
	listenerValue := &fakeListener{}
	host, err := newRuntime(`C:\ProgramData\AgentWorkstationGateway`, syntheticSourceSHA, dependencies{
		readProtected: func(path string, maximum int) ([]byte, error) {
			readPath, readMaximum = path, maximum
			returnedBuffer = append([]byte(nil), encoded...)
			return returnedBuffer, nil
		},
		validateProtected: func(path string, maximum int) error {
			credentialPath, credentialMaximum = path, maximum
			return nil
		},
		systemDirectory: func() (string, error) { return `c:\Windows`, nil },
		listen: func(actual installconfig.Config) (listener, error) {
			if !reflect.DeepEqual(actual, configuration) {
				t.Fatal("listener did not receive the installed configuration")
			}
			return listenerValue, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	if readPath != `C:\ProgramData\AgentWorkstationGateway\state\installation.json` ||
		readMaximum != installconfig.MaxConfigBytes {
		t.Fatal("configuration path or bound was not derived from the installation root")
	}
	if credentialPath != `C:\ProgramData\AgentWorkstationGateway\state\execution-credential.dpapi` ||
		credentialMaximum != process.MaxProtectedCredentialBytes {
		t.Fatal("credential path or bound was not fixed by the runtime")
	}
	if !allZero(returnedBuffer) {
		t.Fatal("protected configuration read buffer was not cleared")
	}
}

func TestNewRuntimeRejectsMissingDependencyAndInvalidRootBeforeStateRead(t *testing.T) {
	assertHostRule(t, func() error {
		_, err := newRuntime(`C:\ProgramData\AgentWorkstationGateway`, syntheticSourceSHA, dependencies{})
		return err
	}(), "startup-dependency-required")
	read := false
	deps := validDependencies(t, validWindowsConfiguration(), &fakeListener{})
	deps.readProtected = func(string, int) ([]byte, error) {
		read = true
		return nil, errors.New("unexpected read")
	}
	_, err := newRuntime(`relative\AWG`, syntheticSourceSHA, deps)
	assertHostRule(t, err, "installation-root-invalid")
	if read {
		t.Fatal("invalid installation root reached protected state")
	}
}

func TestNewRuntimeFailsClosedAtProtectedStateBoundaries(t *testing.T) {
	configuration := validWindowsConfiguration()
	tests := []struct {
		name string
		edit func(*dependencies)
		rule string
	}{
		{name: "configuration read", rule: "installation-config-read-failed", edit: func(deps *dependencies) {
			deps.readProtected = func(string, int) ([]byte, error) { return nil, errors.New("synthetic read failure") }
		}},
		{name: "configuration decode", rule: "installation-config-invalid", edit: func(deps *dependencies) {
			deps.readProtected = func(string, int) ([]byte, error) { return []byte(`{}`), nil }
		}},
		{name: "credential validation", rule: "execution-credential-invalid", edit: func(deps *dependencies) {
			deps.validateProtected = func(string, int) error { return errors.New("synthetic validation failure") }
		}},
		{name: "system directory", rule: "system-directory-query-failed", edit: func(deps *dependencies) {
			deps.systemDirectory = func() (string, error) { return "", errors.New("synthetic query failure") }
		}},
		{name: "source sha", rule: "session-create-failed", edit: func(deps *dependencies) {}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			listener := &fakeListener{}
			deps := validDependencies(t, configuration, listener)
			test.edit(&deps)
			sha := syntheticSourceSHA
			if test.name == "source sha" {
				sha = "request-selected-ref"
			}
			host, err := newRuntime(`C:\ProgramData\AgentWorkstationGateway`, sha, deps)
			if host != nil {
				_ = host.Close()
				t.Fatal("invalid startup produced a runtime")
			}
			assertHostRule(t, err, test.rule)
			if listener.accepts != 0 || listener.closes != 0 {
				t.Fatal("failed startup exposed or closed an uncreated listener")
			}
		})
	}
}

func TestNewRuntimeClosesPartiallyCreatedListener(t *testing.T) {
	listenerValue := &fakeListener{}
	deps := validDependencies(t, validWindowsConfiguration(), listenerValue)
	deps.listen = func(installconfig.Config) (listener, error) {
		return listenerValue, errors.New("synthetic listener failure")
	}
	host, err := newRuntime(`C:\ProgramData\AgentWorkstationGateway`, syntheticSourceSHA, deps)
	if host != nil {
		t.Fatal("partial listener failure produced a runtime")
	}
	assertHostRule(t, err, "listener-create-failed")
	if listenerValue.closes != 1 {
		t.Fatal("partially created listener was not closed")
	}
}

func TestAuthoritySeparationRejectsEveryExecutionOwnedRootOverlap(t *testing.T) {
	layout, err := installplan.WindowsLayout(`C:\ProgramData\AgentWorkstationGateway`)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		alter func(*installconfig.Config)
		rule  string
	}{
		{name: "approved descendant", rule: "installation-overlaps-approved-root", alter: func(config *installconfig.Config) {
			config.ApprovedRoots = []string{layout.Root + `\work`}
		}},
		{name: "approved ancestor", rule: "installation-overlaps-approved-root", alter: func(config *installconfig.Config) {
			config.ApprovedRoots = []string{`C:\ProgramData`}
		}},
		{name: "profile", rule: "installation-overlaps-profile-root", alter: func(config *installconfig.Config) {
			config.ProfileRoot = layout.Root + `\profile`
		}},
		{name: "temp", rule: "installation-overlaps-temp-root", alter: func(config *installconfig.Config) {
			config.TempRoot = layout.Root + `\temp`
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration := validWindowsConfiguration()
			test.alter(&configuration)
			assertHostRule(t, validateAuthoritySeparation(layout, configuration), test.rule)
		})
	}
}

func TestTrustedWindowsEnvironmentUsesOnlyNativeSystemDirectory(t *testing.T) {
	environment, err := trustedWindowsEnvironment(func() (string, error) { return `c:\Windows`, nil })
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{`SystemRoot=C:\Windows`, `WINDIR=C:\Windows`}
	if !reflect.DeepEqual(environment, expected) {
		t.Fatalf("unexpected trusted environment: %#v", environment)
	}
	assertHostRule(t, func() error {
		_, err := trustedWindowsEnvironment(func() (string, error) { return `Windows`, nil })
		return err
	}(), "system-directory-invalid")
}

func TestNativeSystemDirectoryProducesMinimalTrustedEnvironment(t *testing.T) {
	environment, err := trustedWindowsEnvironment(windows.GetSystemWindowsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(environment) != 2 || !strings.HasPrefix(environment[0], "SystemRoot=") ||
		!strings.HasPrefix(environment[1], "WINDIR=") {
		t.Fatalf("unexpected native trusted environment: %#v", environment)
	}
}

func TestProductionNewRejectsOrdinaryConfigurationWithoutEcho(t *testing.T) {
	root := canonicalTestPath(t.TempDir())
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal("could not create state fixture")
	}
	encoded, err := installconfig.MarshalCanonical(validWindowsConfiguration())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(state, "installation.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal("could not create configuration fixture")
	}
	host, err := New(root, syntheticSourceSHA)
	if host != nil {
		_ = host.Close()
		t.Fatal("ordinary user-owned configuration produced a broker runtime")
	}
	assertHostRule(t, err, "installation-config-read-failed")
	if bytes.Contains([]byte(err.Error()), []byte(path)) {
		t.Fatal("protected configuration denial echoed its path")
	}
}

func TestHandleOneAlwaysClosesAcceptedConnection(t *testing.T) {
	connection := &fakeConnection{}
	listener := &fakeListener{connection: connection}
	handler := &fakeHandler{}
	host := &Runtime{listener: listener, handler: handler}
	if err := host.HandleOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	if listener.accepts != 1 || handler.handles != 1 || connection.closes != 1 {
		t.Fatal("successful connection did not complete the owned lifecycle")
	}

	handleFailure := errors.New("synthetic session failure")
	closeFailure := errors.New("synthetic connection close failure")
	connection = &fakeConnection{closeErr: closeFailure}
	host = &Runtime{
		listener: &fakeListener{connection: connection},
		handler:  &fakeHandler{err: handleFailure},
	}
	err := host.HandleOne(context.Background())
	if !errors.Is(err, handleFailure) || !errors.Is(err, closeFailure) || connection.closes != 1 {
		t.Fatal("session and close failures were not both preserved")
	}
}

func TestRuntimeCloseIsIdempotent(t *testing.T) {
	listener := &fakeListener{}
	host := &Runtime{listener: listener, handler: &fakeHandler{}}
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}
	if listener.closes != 1 {
		t.Fatalf("listener closed %d times", listener.closes)
	}
}

func validDependencies(t *testing.T, configuration installconfig.Config, listenerValue listener) dependencies {
	t.Helper()
	encoded, err := installconfig.MarshalCanonical(configuration)
	if err != nil {
		t.Fatal(err)
	}
	return dependencies{
		readProtected:     func(string, int) ([]byte, error) { return append([]byte(nil), encoded...), nil },
		validateProtected: func(string, int) error { return nil },
		systemDirectory:   func() (string, error) { return `C:\Windows`, nil },
		listen:            func(installconfig.Config) (listener, error) { return listenerValue, nil },
	}
}

func validWindowsConfiguration() installconfig.Config {
	return installconfig.Config{
		ConfigVersion: installconfig.CurrentVersion, Platform: platformpath.Windows,
		ControlIdentity: installconfig.Principal{
			Name: "awg-control", Identifier: "S-1-5-21-1000-1000-1000-1001", PrimaryGroupIdentifier: "S-1-5-32-545",
		},
		ExecutionIdentity: installconfig.Principal{
			Name: "awg-exec", Identifier: "S-1-5-21-1000-1000-1000-1002", PrimaryGroupIdentifier: "S-1-5-32-545",
		},
		ApprovedRoots: []string{`C:\Users\Alice\Projects`},
		Shells: []installconfig.ShellBinding{
			{Shell: v1.ShellPwsh, Executable: `C:\Program Files\PowerShell\7\pwsh.exe`},
		},
		ProfileRoot: `C:\ProgramData\AWGProfiles\Exec`, TempRoot: `C:\ProgramData\AWGTemp`,
		PathEntries: []string{`C:\Program Files\PowerShell\7`, `C:\Windows\System32`}, Capabilities: []installconfig.Capability{},
	}
}

func assertHostRule(t *testing.T, err error, rule string) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Rule != rule {
		t.Fatalf("expected %s, got %T / %v", rule, err, err)
	}
}

func allZero(content []byte) bool {
	for _, value := range content {
		if value != 0 {
			return false
		}
	}
	return true
}

func canonicalTestPath(path string) string {
	if len(path) >= 2 && path[1] == ':' && path[0] >= 'a' && path[0] <= 'z' {
		return strings.ToUpper(path[:1]) + path[1:]
	}
	return path
}
