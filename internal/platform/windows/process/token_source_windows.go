//go:build windows

package process

import (
	"context"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

const (
	localAccountDomain     = "."
	logon32LogonBatch      = 4
	logon32ProviderDefault = 0
	profileNoUI            = 1
)

var localAccountNamePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
var logonUserProcedure = windows.NewLazySystemDLL("advapi32.dll").NewProc("LogonUserW")
var loadUserProfileProcedure = windows.NewLazySystemDLL("userenv.dll").NewProc("LoadUserProfileW")
var unloadUserProfileProcedure = windows.NewLazySystemDLL("userenv.dll").NewProc("UnloadUserProfile")

type FileTokenSource struct {
	expected installconfig.Principal
	account  []uint16
	domain   []uint16
	reader   credentialBlobReader
}

var _ TokenSource = (*FileTokenSource)(nil)

// NewFileTokenSource fixes token acquisition to one validated local account
// and one protected absolute credential file. Requests cannot select either.
func NewFileTokenSource(expected installconfig.Principal, credentialPath string) (*FileTokenSource, error) {
	if err := validateTokenSourcePrincipal(expected); err != nil {
		return nil, err
	}
	if err := platformpath.ValidateAbsolute(platformpath.Windows, credentialPath); err != nil {
		return nil, boundaryError("credential-path-invalid")
	}
	account, err := windows.UTF16FromString(expected.Name)
	if err != nil {
		return nil, boundaryError("token-source-principal-invalid")
	}
	domain, err := windows.UTF16FromString(localAccountDomain)
	if err != nil {
		return nil, boundaryError("token-source-domain-invalid")
	}
	return &FileTokenSource{
		expected: expected, account: account, domain: domain,
		reader: protectedCredentialFile{path: credentialPath},
	}, nil
}

func (source *FileTokenSource) Acquire(ctx context.Context, requested installconfig.Principal) (TokenLease, error) {
	if source == nil {
		return nil, boundaryError("token-source-invalid")
	}
	if ctx == nil {
		return nil, boundaryError("token-source-context-required")
	}
	if source.reader == nil || len(source.account) == 0 || len(source.domain) == 0 {
		return nil, boundaryError("token-source-invalid")
	}
	if !sameWindowsPrincipal(source.expected, requested) {
		return nil, boundaryError("token-source-identity-mismatch")
	}
	if err := tokenSourceContextError(ctx); err != nil {
		return nil, err
	}
	protected, err := source.reader.Read()
	if err != nil {
		return nil, boundaryError("credential-read-failed")
	}
	defer zeroBytes(protected)
	plaintext, err := unprotectPassword(protected)
	zeroBytes(protected)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(plaintext)
	password, err := passwordUTF16(plaintext)
	zeroBytes(plaintext)
	if err != nil {
		return nil, err
	}
	defer zeroUTF16(password)

	token, err := batchLogon(&source.account[0], &source.domain[0], &password[0])
	zeroUTF16(password)
	if err != nil {
		return nil, err
	}
	profile, err := loadProfile(token, &source.account[0])
	if err != nil {
		_ = token.Close()
		return nil, err
	}
	lease := &profileTokenLease{token: token, profile: profile}
	if err := tokenSourceContextError(ctx); err != nil {
		_ = lease.Close()
		return nil, err
	}
	return lease, nil
}

func validateTokenSourcePrincipal(principal installconfig.Principal) error {
	if !localAccountNamePattern.MatchString(principal.Name) {
		return boundaryError("token-source-principal-invalid")
	}
	identifier, err := windows.StringToSid(principal.Identifier)
	if err != nil || identifier == nil || !identifier.IsValid() {
		return boundaryError("token-source-principal-invalid")
	}
	primaryGroup, err := windows.StringToSid(principal.PrimaryGroupIdentifier)
	if err != nil || primaryGroup == nil || !primaryGroup.IsValid() {
		return boundaryError("token-source-principal-invalid")
	}
	return nil
}

func sameWindowsPrincipal(left installconfig.Principal, right installconfig.Principal) bool {
	return strings.EqualFold(left.Name, right.Name) &&
		strings.EqualFold(left.Identifier, right.Identifier) &&
		strings.EqualFold(left.PrimaryGroupIdentifier, right.PrimaryGroupIdentifier)
}

func tokenSourceContextError(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return boundaryError("token-source-context-cancelled")
	default:
		return nil
	}
}

func passwordUTF16(password []byte) ([]uint16, error) {
	if !validPassword(password) {
		return nil, boundaryError("credential-plaintext-invalid")
	}
	result := make([]uint16, 0, len(password)+1)
	for len(password) > 0 {
		value, size := utf8.DecodeRune(password)
		if value == utf8.RuneError && size == 1 {
			zeroUTF16(result)
			return nil, boundaryError("credential-plaintext-invalid")
		}
		if value <= 0xffff {
			result = append(result, uint16(value))
		} else {
			high, low := utf16.EncodeRune(value)
			result = append(result, uint16(high), uint16(low))
		}
		password = password[size:]
	}
	return append(result, 0), nil
}

func batchLogon(account *uint16, domain *uint16, password *uint16) (windows.Token, error) {
	var token windows.Token
	success, _, _ := logonUserProcedure.Call(
		uintptr(unsafe.Pointer(account)),
		uintptr(unsafe.Pointer(domain)),
		uintptr(unsafe.Pointer(password)),
		logon32LogonBatch,
		logon32ProviderDefault,
		uintptr(unsafe.Pointer(&token)),
	)
	if success == 0 || token == 0 {
		if token != 0 {
			_ = token.Close()
		}
		return 0, boundaryError("execution-batch-logon-failed")
	}
	return token, nil
}

type profileInformation struct {
	size        uint32
	flags       uint32
	userName    *uint16
	profilePath *uint16
	defaultPath *uint16
	serverName  *uint16
	policyPath  *uint16
	profile     windows.Handle
}

func loadProfile(token windows.Token, account *uint16) (windows.Handle, error) {
	information := profileInformation{
		size: uint32(unsafe.Sizeof(profileInformation{})), flags: profileNoUI, userName: account,
	}
	success, _, _ := loadUserProfileProcedure.Call(
		uintptr(token), uintptr(unsafe.Pointer(&information)),
	)
	if success == 0 || information.profile == 0 {
		return 0, boundaryError("execution-profile-load-failed")
	}
	return information.profile, nil
}

type profileTokenLease struct {
	token     windows.Token
	profile   windows.Handle
	closeOnce sync.Once
	closeErr  error
}

func (lease *profileTokenLease) Token() windows.Token {
	return lease.token
}

func (lease *profileTokenLease) Close() error {
	lease.closeOnce.Do(func() {
		if lease.profile != 0 {
			success, _, _ := unloadUserProfileProcedure.Call(uintptr(lease.token), uintptr(lease.profile))
			if success == 0 {
				lease.closeErr = boundaryError("execution-profile-unload-failed")
			}
			lease.profile = 0
		}
		if lease.token != 0 {
			if err := lease.token.Close(); err != nil && lease.closeErr == nil {
				lease.closeErr = boundaryError("execution-token-close-failed")
			}
			lease.token = 0
		}
	})
	return lease.closeErr
}

//go:noinline
func zeroUTF16(buffer []uint16) {
	for index := range buffer {
		buffer[index] = 0
	}
	runtime.KeepAlive(buffer)
}
