package platformpath

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

type Platform string

const (
	Linux   Platform = "linux"
	Windows Platform = "windows"
)

const MaxPathBytes = 1024

var reservedWindowsNames = regexp.MustCompile(`(?i)^(aux|con|nul|prn|com[1-9]|lpt[1-9])(?:\..*)?$`)

func ValidateAbsolute(platform Platform, value string) error {
	if !utf8.ValidString(value) || len(value) == 0 || len(value) > MaxPathBytes {
		return pathError("invalid-size-or-encoding")
	}
	if strings.ContainsRune(value, '\x00') {
		return pathError("contains-nul")
	}
	switch platform {
	case Linux:
		return validateLinux(value)
	case Windows:
		return validateWindows(value)
	default:
		return pathError("unsupported-platform")
	}
}

func IsFilesystemRoot(platform Platform, value string) bool {
	switch platform {
	case Linux:
		return value == "/"
	case Windows:
		return len(value) == 3 && value[0] >= 'A' && value[0] <= 'Z' && value[1:] == `:\`
	default:
		return false
	}
}

func Equal(platform Platform, left string, right string) bool {
	if platform == Windows {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func Contains(platform Platform, root string, candidate string) bool {
	if Equal(platform, root, candidate) {
		return true
	}
	separator := "/"
	if platform == Windows {
		separator = `\`
	}
	prefix := root
	if !strings.HasSuffix(prefix, separator) {
		prefix += separator
	}
	if platform == Windows {
		return strings.HasPrefix(strings.ToLower(candidate), strings.ToLower(prefix))
	}
	return strings.HasPrefix(candidate, prefix)
}

func Overlaps(platform Platform, left string, right string) bool {
	return Contains(platform, left, right) || Contains(platform, right, left)
}

func validateLinux(value string) error {
	if !strings.HasPrefix(value, "/") {
		return pathError("not-absolute")
	}
	if strings.ContainsRune(value, '\\') {
		return pathError("ambiguous-separator")
	}
	if value == "/" {
		return nil
	}
	return validateSegments(strings.Split(strings.TrimPrefix(value, "/"), "/"), false)
}

func validateWindows(value string) error {
	if len(value) < 3 || value[0] < 'A' || value[0] > 'Z' || value[1] != ':' || value[2] != '\\' {
		return pathError("not-canonical-drive-absolute")
	}
	if strings.ContainsRune(value, '/') {
		return pathError("ambiguous-separator")
	}
	if len(value) == 3 {
		return nil
	}
	return validateSegments(strings.Split(value[3:], `\`), true)
}

func validateSegments(segments []string, windows bool) error {
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return pathError("non-canonical-segment")
		}
		if containsControlCharacter(segment) {
			return pathError("contains-control-character")
		}
		if !windows {
			continue
		}
		if strings.ContainsAny(segment, `<>:"/|?*`) {
			return pathError("invalid-windows-segment")
		}
		if strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") {
			return pathError("ambiguous-windows-segment")
		}
		if reservedWindowsNames.MatchString(segment) {
			return pathError("reserved-windows-name")
		}
	}
	return nil
}

func containsControlCharacter(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}
