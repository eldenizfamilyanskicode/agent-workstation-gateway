package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/publicsafety"
)

const (
	forbiddenLiteralEnv = "AWG_PUBLIC_SAFETY_FORBIDDEN"
	forbiddenRegexEnv   = "AWG_PUBLIC_SAFETY_FORBIDDEN_REGEX"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("awg-public-safety", flag.ContinueOnError)
	flags.SetOutput(stderr)
	repo := flags.String("repo", ".", "Git repository to scan")
	scopeValue := flags.String("scope", "all", "scan scope: all, current, staged, or history")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "unexpected positional arguments")
		return 2
	}

	literals := splitPatternEnv(os.Getenv(forbiddenLiteralEnv))
	regexes := splitPatternEnv(os.Getenv(forbiddenRegexEnv))
	if err := os.Unsetenv(forbiddenLiteralEnv); err != nil {
		fmt.Fprintln(stderr, "could not clear forbidden-literal environment")
		return 2
	}
	if err := os.Unsetenv(forbiddenRegexEnv); err != nil {
		fmt.Fprintln(stderr, "could not clear forbidden-regex environment")
		return 2
	}

	scope, err := publicsafety.ParseScope(*scopeValue)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	findings, err := publicsafety.Scan(ctx, publicsafety.Options{
		Repo:              *repo,
		Scope:             scope,
		ForbiddenLiterals: literals,
		ForbiddenRegexes:  regexes,
	})
	if err != nil {
		fmt.Fprintf(stderr, "public safety scan failed: %v\n", err)
		return 2
	}

	for _, finding := range findings {
		path := redactPrivate(finding.Path, literals, regexes)
		revision := redactPrivate(finding.Revision, literals, regexes)
		fmt.Fprintf(stdout, "scope=%s rule=%s path=%q revision=%q\n", finding.Scope, finding.Rule, path, revision)
	}
	if len(findings) != 0 {
		fmt.Fprintf(stderr, "public safety scan failed: %d finding(s)\n", len(findings))
		return 1
	}

	fmt.Fprintln(stdout, "public safety scan passed")
	return 0
}

func splitPatternEnv(value string) []string {
	if value == "" {
		return nil
	}
	lines := strings.Split(strings.ReplaceAll(value, "\r\n", "\n"), "\n")
	patterns := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		if strings.TrimSpace(line) != "" {
			patterns = append(patterns, line)
		}
	}
	return patterns
}

func redactPrivate(value string, literals, regexes []string) string {
	redacted := value
	for _, literal := range literals {
		if literal != "" {
			redacted = strings.ReplaceAll(redacted, literal, "<redacted>")
		}
	}
	for _, pattern := range regexes {
		re, err := regexp.Compile(pattern)
		if err == nil {
			redacted = re.ReplaceAllString(redacted, "<redacted>")
		}
	}
	return redacted
}
