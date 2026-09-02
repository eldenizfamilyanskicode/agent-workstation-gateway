package v1

import (
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

var identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

var supportedShells = map[Shell]struct{}{
	ShellBash:       {},
	ShellCmd:        {},
	ShellGitBash:    {},
	ShellPowerShell: {},
	ShellPwsh:       {},
}

var reservedWindowsNames = map[string]struct{}{
	"aux":  {},
	"con":  {},
	"nul":  {},
	"prn":  {},
	"com1": {},
	"com2": {},
	"com3": {},
	"com4": {},
	"com5": {},
	"com6": {},
	"com7": {},
	"com8": {},
	"com9": {},
	"lpt1": {},
	"lpt2": {},
	"lpt3": {},
	"lpt4": {},
	"lpt5": {},
	"lpt6": {},
	"lpt7": {},
	"lpt8": {},
	"lpt9": {},
}

var forbiddenArtifactSegments = map[string]struct{}{
	".aws":     {},
	".azure":   {},
	".git":     {},
	".gnupg":   {},
	".kube":    {},
	".runtime": {},
	".ssh":     {},
}

func ValidateRequest(request Request) error {
	if request.ProtocolVersion != Version {
		return validationError("protocol_version", "unsupported-version")
	}
	if err := validateIdentifier("request_id", request.RequestID); err != nil {
		return err
	}
	if err := validateIdentifier("session_id", request.SessionID); err != nil {
		return err
	}
	if err := validateIdentifier("actor", request.Actor); err != nil {
		return err
	}
	if _, supported := supportedShells[request.Shell]; !supported {
		return validationError("shell", "unsupported-shell")
	}
	if err := validateWorkingDirectory(request.WorkingDirectory); err != nil {
		return err
	}
	if err := validateScript(request.Script); err != nil {
		return err
	}
	if request.TimeoutSeconds < MinTimeoutSeconds || request.TimeoutSeconds > MaxTimeoutSeconds {
		return validationError("timeout_seconds", "outside-allowed-range")
	}
	if request.MaxOutputBytes < MinOutputBytes || request.MaxOutputBytes > MaxOutputBytes {
		return validationError("max_output_bytes", "outside-allowed-range")
	}
	return validateArtifactSelections(request.Artifacts)
}

func validateIdentifier(field string, value string) error {
	if len(value) == 0 || len(value) > MaxIdentifierBytes || !identifierPattern.MatchString(value) {
		return validationError(field, "invalid-identifier")
	}
	return nil
}

func validateScript(script string) error {
	if !utf8.ValidString(script) {
		return validationError("script", "invalid-utf8")
	}
	if len(script) == 0 || len(script) > MaxScriptBytes {
		return validationError("script", "outside-size-limit")
	}
	if strings.TrimSpace(script) == "" {
		return validationError("script", "empty-script")
	}
	if strings.ContainsRune(script, '\x00') {
		return validationError("script", "contains-nul")
	}
	return nil
}

func validateWorkingDirectory(workingDirectory string) error {
	if !utf8.ValidString(workingDirectory) || len(workingDirectory) == 0 || len(workingDirectory) > MaxWorkingPathBytes {
		return validationError("working_directory", "invalid-size-or-encoding")
	}
	if strings.ContainsRune(workingDirectory, '\x00') {
		return validationError("working_directory", "contains-nul")
	}
	if strings.HasPrefix(workingDirectory, "/") {
		return validatePOSIXWorkingDirectory(workingDirectory)
	}
	if len(workingDirectory) >= 3 && isASCIILetter(workingDirectory[0]) && workingDirectory[1] == ':' && workingDirectory[2] == '\\' {
		return validateWindowsWorkingDirectory(workingDirectory)
	}
	return validationError("working_directory", "not-supported-absolute-path")
}

func validatePOSIXWorkingDirectory(workingDirectory string) error {
	if workingDirectory == "/" {
		return nil
	}
	if strings.ContainsRune(workingDirectory, '\\') {
		return validationError("working_directory", "ambiguous-posix-separator")
	}
	segments := strings.Split(strings.TrimPrefix(workingDirectory, "/"), "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return validationError("working_directory", "non-canonical-posix-segment")
		}
		if containsControlCharacter(segment) {
			return validationError("working_directory", "contains-control-character")
		}
	}
	return nil
}

func validateWindowsWorkingDirectory(workingDirectory string) error {
	if len(workingDirectory) == 3 {
		return nil
	}
	segments := strings.Split(workingDirectory[3:], "\\")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return validationError("working_directory", "non-canonical-windows-segment")
		}
		if containsControlCharacter(segment) || strings.ContainsAny(segment, `<>:"/|?*`) {
			return validationError("working_directory", "invalid-windows-segment")
		}
		if strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") {
			return validationError("working_directory", "ambiguous-windows-segment")
		}
		baseName := strings.ToLower(strings.SplitN(segment, ".", 2)[0])
		if _, reserved := reservedWindowsNames[baseName]; reserved {
			return validationError("working_directory", "reserved-windows-name")
		}
	}
	return nil
}

func validateArtifactSelections(artifacts []ArtifactSelection) error {
	if artifacts == nil {
		return validationError("artifacts", "required-array")
	}
	if len(artifacts) > MaxArtifactGroups {
		return validationError("artifacts", "too-many-groups")
	}
	groupNames := make(map[string]struct{}, len(artifacts))
	totalPaths := 0
	for _, artifact := range artifacts {
		if len(artifact.Name) == 0 || len(artifact.Name) > MaxArtifactGroupBytes || !identifierPattern.MatchString(artifact.Name) {
			return validationError("artifacts.name", "invalid-identifier")
		}
		if _, exists := groupNames[artifact.Name]; exists {
			return validationError("artifacts.name", "duplicate-group")
		}
		groupNames[artifact.Name] = struct{}{}
		if artifact.Paths == nil || len(artifact.Paths) == 0 || len(artifact.Paths) > MaxArtifactPaths {
			return validationError("artifacts.paths", "outside-count-limit")
		}
		seenPaths := make(map[string]struct{}, len(artifact.Paths))
		for _, artifactPath := range artifact.Paths {
			if err := validateArtifactPath(artifactPath); err != nil {
				return err
			}
			if _, exists := seenPaths[artifactPath]; exists {
				return validationError("artifacts.paths", "duplicate-path")
			}
			seenPaths[artifactPath] = struct{}{}
			totalPaths++
		}
	}
	if totalPaths > MaxTotalArtifactPaths {
		return validationError("artifacts.paths", "too-many-total-paths")
	}
	return nil
}

// ValidateArtifactSelections applies the standalone artifact request boundary
// for native collectors that receive an already-authorized launch plan.
func ValidateArtifactSelections(artifacts []ArtifactSelection) error {
	return validateArtifactSelections(artifacts)
}

func validateArtifactPath(artifactPath string) error {
	return validateRelativeArtifactPath("artifacts.paths", artifactPath, MaxArtifactPathBytes, true)
}

func validateArtifactFilePath(artifactPath string) error {
	return validateRelativeArtifactPath("artifacts.files.path", artifactPath, MaxArtifactFilePathBytes, false)
}

// ValidateArtifactFilePath applies the canonical reported-file path boundary
// before a native collector adds filesystem-discovered names to a manifest.
func ValidateArtifactFilePath(artifactPath string) error {
	return validateArtifactFilePath(artifactPath)
}

func validateArtifactOmissionPattern(artifactPath string) error {
	return validateRelativeArtifactPath("artifacts.omissions.pattern", artifactPath, MaxArtifactPathBytes, true)
}

func validateRelativeArtifactPath(field string, artifactPath string, maximumBytes int, allowGlob bool) error {
	if !utf8.ValidString(artifactPath) || len(artifactPath) == 0 || len(artifactPath) > maximumBytes {
		return validationError(field, "invalid-size-or-encoding")
	}
	if strings.HasPrefix(artifactPath, "/") || strings.ContainsAny(artifactPath, "\\:\x00") {
		return validationError(field, "not-safe-relative-path")
	}
	if allowGlob {
		if _, err := path.Match(artifactPath, "synthetic/path"); err != nil {
			return validationError(field, "invalid-glob-syntax")
		}
	} else if strings.ContainsAny(artifactPath, "*?[") {
		return validationError(field, "glob-in-file-path")
	}
	segments := strings.Split(artifactPath, "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return validationError(field, "non-canonical-segment")
		}
		if containsControlCharacter(segment) {
			return validationError(field, "contains-control-character")
		}
		lowerSegment := strings.ToLower(segment)
		if _, forbidden := forbiddenArtifactSegments[lowerSegment]; forbidden {
			return validationError(field, "sensitive-segment")
		}
		if lowerSegment == ".env" || strings.HasPrefix(lowerSegment, ".env.") {
			return validationError(field, "sensitive-segment")
		}
	}
	return nil
}

func isASCIILetter(value byte) bool {
	return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z')
}

func containsControlCharacter(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}
