//go:build windows

package process

import (
	"sort"
	"strings"
	"unicode/utf16"

	"golang.org/x/sys/windows"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/shellinvoke"
)

const maxWindowsBlockCodeUnits = 32767

func buildCommandLine(invocation shellinvoke.Invocation) (*uint16, *uint16, error) {
	executable := invocation.Executable()
	arguments := append([]string{executable}, invocation.Arguments()...)
	commandLine := windows.ComposeCommandLine(arguments)
	if len(utf16.Encode([]rune(commandLine))) >= maxWindowsBlockCodeUnits {
		return nil, nil, boundaryError("command-line-too-large")
	}
	executablePointer, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return nil, nil, boundaryError("invalid-executable")
	}
	commandLinePointer, err := windows.UTF16PtrFromString(commandLine)
	if err != nil {
		return nil, nil, boundaryError("invalid-command-line")
	}
	return executablePointer, commandLinePointer, nil
}

func buildEnvironmentBlock(environment []string) ([]uint16, error) {
	entries := append([]string(nil), environment...)
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		separator := strings.IndexByte(entry, '=')
		if separator <= 0 || strings.ContainsRune(entry, '\x00') {
			return nil, boundaryError("invalid-environment")
		}
		name := strings.ToUpper(entry[:separator])
		if _, duplicate := seen[name]; duplicate {
			return nil, boundaryError("duplicate-environment")
		}
		seen[name] = struct{}{}
	}
	sort.Slice(entries, func(left int, right int) bool {
		leftFolded := strings.ToUpper(entries[left])
		rightFolded := strings.ToUpper(entries[right])
		if leftFolded == rightFolded {
			return entries[left] < entries[right]
		}
		return leftFolded < rightFolded
	})
	joined := strings.Join(entries, "\x00")
	block := utf16.Encode([]rune(joined))
	block = append(block, 0, 0)
	if len(block) > maxWindowsBlockCodeUnits {
		return nil, boundaryError("environment-too-large")
	}
	return block, nil
}
