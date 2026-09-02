package workloadenv

import (
	"regexp"
	"sort"
	"strings"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platformpath"
)

const (
	maxBaseEntries = 512
	maxEntryBytes  = 32 * 1024
)

type Context struct {
	RequestID string
	SessionID string
	AttemptID string
}

var identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
var localePattern = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,64}$`)
var timeZonePattern = regexp.MustCompile(`^[A-Za-z0-9_+:/.-]{1,128}$`)
var windowsTextPattern = regexp.MustCompile(`^[A-Za-z0-9 _.,()/_-]{1,128}$`)
var windowsPathExtensionsPattern = regexp.MustCompile(`^(?:\.[A-Za-z0-9]{1,16})(?:;\.[A-Za-z0-9]{1,16}){0,31}$`)

var windowsSafeBaseNames = map[string]string{
	"number_of_processors":   "NUMBER_OF_PROCESSORS",
	"os":                     "OS",
	"pathext":                "PATHEXT",
	"processor_architecture": "PROCESSOR_ARCHITECTURE",
	"processor_identifier":   "PROCESSOR_IDENTIFIER",
	"processor_level":        "PROCESSOR_LEVEL",
	"processor_revision":     "PROCESSOR_REVISION",
	"systemroot":             "SystemRoot",
	"windir":                 "WINDIR",
}

var linuxSafeBaseNames = map[string]string{
	"LANG":   "LANG",
	"LC_ALL": "LC_ALL",
	"TZ":     "TZ",
}

func Build(configuration installconfig.Config, safeBase []string, context Context) ([]string, error) {
	if err := installconfig.Validate(configuration); err != nil {
		return nil, environmentError("config", "invalid-installation-config")
	}
	if !identifierPattern.MatchString(context.RequestID) {
		return nil, environmentError("request_id", "invalid-identifier")
	}
	if !identifierPattern.MatchString(context.SessionID) {
		return nil, environmentError("session_id", "invalid-identifier")
	}
	if !identifierPattern.MatchString(context.AttemptID) {
		return nil, environmentError("attempt_id", "invalid-identifier")
	}
	if len(safeBase) > maxBaseEntries {
		return nil, environmentError("safe_base", "too-many-entries")
	}

	projected, err := projectSafeBase(configuration.Platform, safeBase)
	if err != nil {
		return nil, err
	}
	if configuration.Platform == platformpath.Windows {
		systemRoot, hasSystemRoot := projected["SystemRoot"]
		windowsDirectory, hasWindowsDirectory := projected["WINDIR"]
		if !hasSystemRoot || !hasWindowsDirectory {
			return nil, environmentError("safe_base", "missing-windows-system-paths")
		}
		if !platformpath.Equal(platformpath.Windows, systemRoot, windowsDirectory) {
			return nil, environmentError("safe_base", "inconsistent-windows-system-paths")
		}
	}
	setGatewayValues(configuration, context, projected)
	return sortedEnvironment(configuration.Platform, projected), nil
}

func projectSafeBase(platform platformpath.Platform, safeBase []string) (map[string]string, error) {
	projected := make(map[string]string)
	seen := make(map[string]struct{})
	for _, entry := range safeBase {
		if len(entry) == 0 || len(entry) > maxEntryBytes || strings.ContainsRune(entry, '\x00') {
			return nil, environmentError("safe_base", "invalid-entry")
		}
		if platform == platformpath.Windows && strings.HasPrefix(entry, "=") {
			continue
		}
		separator := strings.IndexByte(entry, '=')
		if separator <= 0 {
			return nil, environmentError("safe_base", "invalid-entry")
		}
		name := entry[:separator]
		value := entry[separator+1:]
		lookupName := name
		allowedNames := linuxSafeBaseNames
		if platform == platformpath.Windows {
			lookupName = strings.ToLower(name)
			allowedNames = windowsSafeBaseNames
		}
		canonicalName, allowed := allowedNames[lookupName]
		if !allowed {
			continue
		}
		seenName := canonicalName
		if platform == platformpath.Windows {
			seenName = strings.ToLower(canonicalName)
		}
		if _, duplicate := seen[seenName]; duplicate {
			return nil, environmentError("safe_base", "duplicate-allowed-key")
		}
		if err := validateSafeBaseValue(platform, canonicalName, value); err != nil {
			return nil, err
		}
		seen[seenName] = struct{}{}
		projected[canonicalName] = value
	}
	return projected, nil
}

func validateSafeBaseValue(platform platformpath.Platform, name string, value string) error {
	if platform == platformpath.Linux {
		if (name == "LANG" || name == "LC_ALL") && !localePattern.MatchString(value) {
			return environmentError("safe_base", "invalid-locale")
		}
		if name == "TZ" && !timeZonePattern.MatchString(value) {
			return environmentError("safe_base", "invalid-time-zone")
		}
		return nil
	}
	if name == "SystemRoot" || name == "WINDIR" {
		if err := platformpath.ValidateAbsolute(platformpath.Windows, value); err != nil {
			return environmentError("safe_base", "invalid-system-path")
		}
		return nil
	}
	if name == "PATHEXT" {
		if !windowsPathExtensionsPattern.MatchString(value) {
			return environmentError("safe_base", "invalid-path-extensions")
		}
		return nil
	}
	if !windowsTextPattern.MatchString(value) {
		return environmentError("safe_base", "invalid-system-value")
	}
	return nil
}

func setGatewayValues(configuration installconfig.Config, context Context, environment map[string]string) {
	pathSeparator := ":"
	if configuration.Platform == platformpath.Windows {
		pathSeparator = ";"
		environment["USERPROFILE"] = configuration.ProfileRoot
		environment["HOME"] = configuration.ProfileRoot
		environment["TEMP"] = configuration.TempRoot
		environment["TMP"] = configuration.TempRoot
		environment["USERNAME"] = configuration.ExecutionIdentity.Name
	} else {
		environment["HOME"] = configuration.ProfileRoot
		environment["TMPDIR"] = configuration.TempRoot
		environment["USER"] = configuration.ExecutionIdentity.Name
		environment["LOGNAME"] = configuration.ExecutionIdentity.Name
	}
	environment["PATH"] = strings.Join(configuration.PathEntries, pathSeparator)
	environment["AWG_REQUEST_ID"] = context.RequestID
	environment["AWG_SESSION_ID"] = context.SessionID
	environment["AWG_ATTEMPT_ID"] = context.AttemptID
}

func sortedEnvironment(platform platformpath.Platform, environment map[string]string) []string {
	names := make([]string, 0, len(environment))
	for name := range environment {
		names = append(names, name)
	}
	sort.Slice(names, func(left int, right int) bool {
		if platform == platformpath.Windows {
			return strings.ToLower(names[left]) < strings.ToLower(names[right])
		}
		return names[left] < names[right]
	})
	result := make([]string, 0, len(names))
	for _, name := range names {
		result = append(result, name+"="+environment[name])
	}
	return result
}
