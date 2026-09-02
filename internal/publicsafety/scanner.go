package publicsafety

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Scope string

const (
	ScopeAll     Scope = "all"
	ScopeCurrent Scope = "current"
	ScopeStaged  Scope = "staged"
	ScopeHistory Scope = "history"
)

const maxScannableBytes int64 = 8 << 20

type Options struct {
	Repo              string
	Scope             Scope
	ForbiddenLiterals []string
	ForbiddenRegexes  []string
}

type Finding struct {
	Scope    Scope
	Rule     string
	Path     string
	Revision string
}

type privateRegexRule struct {
	id string
	re *regexp.Regexp
}

type compiledOptions struct {
	root              string
	scope             Scope
	privateLiterals   []string
	privateRegexRules []privateRegexRule
}

type contentRule struct {
	id string
	re *regexp.Regexp
}

var contentRules = []contentRule{
	{id: "secret-private-key", re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)},
	{id: "secret-pgp-private-key", re: regexp.MustCompile(`-----BEGIN PGP PRIVATE ` + `KEY BLOCK-----`)},
	{id: "secret-github-token", re: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`)},
	{id: "secret-github-fine-grained-token", re: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`)},
}

func ParseScope(value string) (Scope, error) {
	switch Scope(strings.ToLower(strings.TrimSpace(value))) {
	case ScopeAll:
		return ScopeAll, nil
	case ScopeCurrent:
		return ScopeCurrent, nil
	case ScopeStaged:
		return ScopeStaged, nil
	case ScopeHistory:
		return ScopeHistory, nil
	default:
		return "", fmt.Errorf("unknown scan scope %q", value)
	}
}

func Scan(ctx context.Context, options Options) ([]Finding, error) {
	compiled, err := compileOptions(ctx, options)
	if err != nil {
		return nil, err
	}

	var findings []Finding
	if compiled.scope == ScopeAll || compiled.scope == ScopeCurrent {
		current, err := scanCurrent(ctx, compiled)
		if err != nil {
			return nil, err
		}
		findings = append(findings, current...)
	}
	if compiled.scope == ScopeAll || compiled.scope == ScopeStaged {
		staged, err := scanStaged(ctx, compiled)
		if err != nil {
			return nil, err
		}
		findings = append(findings, staged...)
	}
	if compiled.scope == ScopeAll || compiled.scope == ScopeHistory {
		history, err := scanHistory(ctx, compiled)
		if err != nil {
			return nil, err
		}
		findings = append(findings, history...)
	}

	findings = deduplicate(findings)
	sort.Slice(findings, func(i, j int) bool {
		left := findings[i]
		right := findings[j]
		if left.Scope != right.Scope {
			return left.Scope < right.Scope
		}
		if left.Revision != right.Revision {
			return left.Revision < right.Revision
		}
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		return left.Rule < right.Rule
	})
	return findings, nil
}

func compileOptions(ctx context.Context, options Options) (compiledOptions, error) {
	scope := options.Scope
	if scope == "" {
		scope = ScopeAll
	}
	if _, err := ParseScope(string(scope)); err != nil {
		return compiledOptions{}, err
	}

	repo := options.Repo
	if repo == "" {
		repo = "."
	}
	rootBytes, err := gitOutput(ctx, repo, "rev-parse", "--show-toplevel")
	if err != nil {
		return compiledOptions{}, err
	}
	root := strings.TrimSpace(string(rootBytes))
	if root == "" {
		return compiledOptions{}, errors.New("git repository root is empty")
	}

	literals := make([]string, 0, len(options.ForbiddenLiterals))
	for _, value := range options.ForbiddenLiterals {
		if value = strings.TrimSpace(value); value != "" {
			literals = append(literals, value)
		}
	}

	regexes := make([]privateRegexRule, 0, len(options.ForbiddenRegexes))
	for index, value := range options.ForbiddenRegexes {
		if value = strings.TrimSpace(value); value == "" {
			continue
		}
		re, err := regexp.Compile(value)
		if err != nil {
			return compiledOptions{}, fmt.Errorf("invalid operator regex %d", index+1)
		}
		regexes = append(regexes, privateRegexRule{
			id: fmt.Sprintf("operator-regex-%02d", index+1),
			re: re,
		})
	}

	return compiledOptions{
		root:              root,
		scope:             scope,
		privateLiterals:   literals,
		privateRegexRules: regexes,
	}, nil
}

func scanCurrent(ctx context.Context, options compiledOptions) ([]Finding, error) {
	output, err := gitOutput(ctx, options.root, "ls-files", "-z")
	if err != nil {
		return nil, err
	}

	var findings []Finding
	for _, path := range splitNUL(output) {
		data, exists, err := readWorkingTreeEntry(options.root, path)
		if err != nil {
			return nil, fmt.Errorf("read tracked path %q: %w", path, err)
		}
		if !exists {
			continue
		}
		findings = append(findings, scanEntry(options, ScopeCurrent, path, "", data)...)
	}
	return findings, nil
}

func scanStaged(ctx context.Context, options compiledOptions) ([]Finding, error) {
	changedOutput, err := gitOutput(ctx, options.root, "diff", "--cached", "--name-only", "-z", "--diff-filter=ACMRT")
	if err != nil {
		return nil, err
	}
	changed := splitNUL(changedOutput)
	if len(changed) == 0 {
		return nil, nil
	}

	stagesOutput, err := gitOutput(ctx, options.root, "ls-files", "--stage", "-z")
	if err != nil {
		return nil, err
	}
	stageBlobs := parseStageBlobs(stagesOutput)

	var findings []Finding
	for _, path := range changed {
		sha, ok := stageBlobs[path]
		if !ok {
			return nil, fmt.Errorf("staged blob missing for %q", path)
		}
		data, err := gitOutput(ctx, options.root, "cat-file", "blob", sha)
		if err != nil {
			return nil, err
		}
		findings = append(findings, scanEntry(options, ScopeStaged, path, "index", data)...)
	}
	return findings, nil
}

func scanHistory(ctx context.Context, options compiledOptions) ([]Finding, error) {
	commitOutput, err := gitOutput(ctx, options.root, "rev-list", "--all")
	if err != nil {
		return nil, err
	}
	commits := strings.Fields(string(commitOutput))

	var findings []Finding
	genericSeen := make(map[string]bool)
	workflowSeen := make(map[string]bool)

	for _, commit := range commits {
		commitData, err := gitOutput(ctx, options.root, "cat-file", "commit", commit)
		if err != nil {
			return nil, err
		}
		findings = append(findings, scanData(options, ScopeHistory, "<commit>", commit, commitData)...)

		treeOutput, err := gitOutput(ctx, options.root, "ls-tree", "-r", "-l", "-z", "--full-tree", commit)
		if err != nil {
			return nil, err
		}
		entries, err := parseTreeEntries(treeOutput)
		if err != nil {
			return nil, err
		}

		for _, entry := range entries {
			findings = append(findings, scanPath(options, ScopeHistory, entry.path, commit)...)
			workflow := isActiveWorkflow(entry.path)
			needGeneric := !genericSeen[entry.sha]
			needWorkflow := workflow && !workflowSeen[entry.sha]
			if !needGeneric && !needWorkflow {
				continue
			}
			if entry.size > maxScannableBytes {
				findings = append(findings, Finding{Scope: ScopeHistory, Rule: "content-too-large-for-safety-scan", Path: entry.path, Revision: commit})
				genericSeen[entry.sha] = true
				if workflow {
					workflowSeen[entry.sha] = true
				}
				continue
			}
			data, err := gitOutput(ctx, options.root, "cat-file", "blob", entry.sha)
			if err != nil {
				return nil, err
			}
			if needGeneric {
				findings = append(findings, scanData(options, ScopeHistory, entry.path, commit, data)...)
				genericSeen[entry.sha] = true
			}
			if needWorkflow {
				findings = append(findings, scanWorkflow(ScopeHistory, entry.path, commit, data)...)
				workflowSeen[entry.sha] = true
			}
		}
	}
	return findings, nil
}

func scanEntry(options compiledOptions, scope Scope, path, revision string, data []byte) []Finding {
	findings := scanPath(options, scope, path, revision)
	if int64(len(data)) > maxScannableBytes {
		return append(findings, Finding{Scope: scope, Rule: "content-too-large-for-safety-scan", Path: path, Revision: revision})
	}
	findings = append(findings, scanData(options, scope, path, revision, data)...)
	if isActiveWorkflow(path) {
		findings = append(findings, scanWorkflow(scope, path, revision, data)...)
	}
	return findings
}

func scanPath(options compiledOptions, scope Scope, path, revision string) []Finding {
	var findings []Finding
	if rule := forbiddenPathRule(path); rule != "" {
		findings = append(findings, Finding{Scope: scope, Rule: rule, Path: path, Revision: revision})
	}
	findings = append(findings, scanPrivateData(options, scope, path, revision, []byte(path))...)
	return findings
}

func scanData(options compiledOptions, scope Scope, path, revision string, data []byte) []Finding {
	var findings []Finding
	for _, rule := range contentRules {
		if rule.re.Find(data) != nil {
			findings = append(findings, Finding{Scope: scope, Rule: rule.id, Path: path, Revision: revision})
		}
	}
	findings = append(findings, scanPrivateData(options, scope, path, revision, data)...)
	return findings
}

func scanPrivateData(options compiledOptions, scope Scope, path, revision string, data []byte) []Finding {
	var findings []Finding
	for index, value := range options.privateLiterals {
		if bytes.Contains(data, []byte(value)) {
			findings = append(findings, Finding{
				Scope:    scope,
				Rule:     fmt.Sprintf("operator-literal-%02d", index+1),
				Path:     path,
				Revision: revision,
			})
		}
	}
	for _, rule := range options.privateRegexRules {
		if rule.re.Find(data) != nil {
			findings = append(findings, Finding{Scope: scope, Rule: rule.id, Path: path, Revision: revision})
		}
	}
	return findings
}

func scanWorkflow(scope Scope, path, revision string, data []byte) []Finding {
	lower := bytes.ToLower(data)
	var findings []Finding
	add := func(rule string) {
		findings = append(findings, Finding{Scope: scope, Rule: rule, Path: path, Revision: revision})
	}
	if bytes.Contains(lower, []byte("self-hosted")) {
		add("workflow-self-hosted")
	}
	if bytes.Contains(lower, []byte("pull_request_target")) {
		add("workflow-pull-request-target")
	}
	if bytes.Contains(lower, []byte("${{ secrets.")) {
		add("workflow-secret-reference")
	}

	lines := strings.Split(string(data), "\n")
	hasTopLevelPermissions := false
	hasTopLevelContentsRead := false
	permissionIndent := -1
	checkoutCount := 0
	persistCredentialsFalse := 0
	fetchDepthZero := 0
	runnerCount := 0

	for _, rawLine := range lines {
		rawLine = strings.TrimSuffix(rawLine, "\r")
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(rawLine) - len(strings.TrimLeft(rawLine, " \t"))
		clean := stripWorkflowComment(trimmed)
		lowerClean := strings.ToLower(clean)

		if permissionIndent >= 0 && indent <= permissionIndent {
			permissionIndent = -1
		}
		if strings.HasPrefix(lowerClean, "permissions:") {
			value := strings.TrimSpace(clean[len("permissions:"):])
			if indent == 0 {
				hasTopLevelPermissions = true
			}
			if value == "" {
				permissionIndent = indent
			} else if strings.EqualFold(value, "write-all") {
				add("workflow-write-permission")
			}
			continue
		}
		if permissionIndent >= 0 && indent > permissionIndent {
			key, value, ok := workflowKeyValue(clean)
			if ok {
				if permissionIndent == 0 && strings.EqualFold(key, "contents") && strings.EqualFold(value, "read") {
					hasTopLevelContentsRead = true
				}
				if strings.EqualFold(value, "write") || strings.EqualFold(value, "write-all") {
					add("workflow-write-permission")
				}
			}
		}

		if value, ok := workflowScalar(clean, "runs-on"); ok {
			runnerCount++
			if value != "ubuntu-latest" && value != "windows-latest" {
				add("workflow-runner-not-allowlisted")
			}
		}
		if value, ok := workflowUses(clean); ok {
			if strings.HasPrefix(strings.ToLower(value), "actions/checkout@") {
				checkoutCount++
			}
			if !workflowActionPinned(value) {
				add("workflow-unpinned-action")
			}
		}
		if value, ok := workflowScalar(clean, "persist-credentials"); ok && strings.EqualFold(value, "false") {
			persistCredentialsFalse++
		}
		if value, ok := workflowScalar(clean, "fetch-depth"); ok && value == "0" {
			fetchDepthZero++
		}
	}

	if !hasTopLevelPermissions {
		add("workflow-missing-permissions")
	} else if !hasTopLevelContentsRead {
		add("workflow-missing-contents-read")
	}
	if runnerCount == 0 {
		add("workflow-missing-hosted-runner")
	}
	if persistCredentialsFalse < checkoutCount {
		add("workflow-checkout-persists-credentials")
	}
	if fetchDepthZero < checkoutCount {
		add("workflow-checkout-shallow-history")
	}
	return findings
}

func stripWorkflowComment(line string) string {
	if index := strings.Index(line, " #"); index >= 0 {
		line = line[:index]
	}
	return strings.TrimSpace(line)
}

func workflowScalar(line, key string) (string, bool) {
	prefix := strings.ToLower(key) + ":"
	if !strings.HasPrefix(strings.ToLower(line), prefix) {
		return "", false
	}
	value := strings.TrimSpace(line[len(prefix):])
	value = strings.Trim(value, "'\"")
	return value, true
}

func workflowKeyValue(line string) (string, string, bool) {
	key, value, ok := strings.Cut(line, ":")
	if !ok {
		return "", "", false
	}
	return strings.TrimSpace(key), strings.Trim(strings.TrimSpace(value), "'\""), true
}

func workflowUses(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "-") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "-"))
	}
	value, ok := workflowScalar(line, "uses")
	return value, ok
}

func workflowActionPinned(value string) bool {
	if strings.HasPrefix(value, "./") {
		return true
	}
	separator := strings.LastIndex(value, "@")
	if separator < 1 || separator == len(value)-1 {
		return false
	}
	revision := value[separator+1:]
	if len(revision) != 40 {
		return false
	}
	for _, char := range revision {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
			return false
		}
	}
	return true
}
func forbiddenPathRule(path string) string {
	normalized := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	padded := "/" + strings.TrimPrefix(normalized, "/")
	if strings.Contains(padded, "/.runtime/requests/") || strings.Contains(padded, "/.runtime/results/") || strings.HasSuffix(padded, "/.runtime/session.json") {
		return "forbidden-runtime-state"
	}

	segments := strings.Split(strings.Trim(normalized, "/"), "/")
	for _, segment := range segments {
		switch segment {
		case ".credentials", ".credentials_rsaparams", ".runner", ".runner_migrated", ".service", ".git-credentials", "credentials.json", "service-account.json", "id_rsa", "id_ed25519", "id_ecdsa":
			return "credential-bearing-path"
		}
	}

	base := ""
	if len(segments) > 0 {
		base = segments[len(segments)-1]
	}
	if base == ".env" || (strings.HasPrefix(base, ".env.") && base != ".env.example" && base != ".env.sample" && base != ".env.template") {
		return "environment-secret-file"
	}
	if strings.HasSuffix(base, ".p12") || strings.HasSuffix(base, ".pfx") {
		return "credential-bearing-path"
	}
	return ""
}

func isActiveWorkflow(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	if !strings.HasPrefix(normalized, ".github/workflows/") {
		return false
	}
	ext := filepath.Ext(normalized)
	return ext == ".yml" || ext == ".yaml"
}

func readWorkingTreeEntry(root, path string) ([]byte, bool, error) {
	fullPath := filepath.Join(root, filepath.FromSlash(path))
	info, err := os.Lstat(fullPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(fullPath)
		if err != nil {
			return nil, false, err
		}
		return []byte(target), true, nil
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("unsupported tracked file type %s", info.Mode().Type())
	}
	if info.Size() > maxScannableBytes {
		return make([]byte, maxScannableBytes+1), true, nil
	}
	data, err := os.ReadFile(fullPath)
	return data, true, err
}

type treeEntry struct {
	sha  string
	size int64
	path string
}

func parseTreeEntries(output []byte) ([]treeEntry, error) {
	var entries []treeEntry
	for _, record := range splitNUL(output) {
		header, path, ok := strings.Cut(record, "\t")
		if !ok {
			return nil, errors.New("invalid git ls-tree record")
		}
		fields := strings.Fields(header)
		if len(fields) < 4 || fields[1] != "blob" {
			continue
		}
		size, err := strconv.ParseInt(fields[3], 10, 64)
		if err != nil {
			return nil, errors.New("invalid git ls-tree blob size")
		}
		entries = append(entries, treeEntry{sha: fields[2], size: size, path: path})
	}
	return entries, nil
}

func parseStageBlobs(output []byte) map[string]string {
	blobs := make(map[string]string)
	for _, record := range splitNUL(output) {
		header, path, ok := strings.Cut(record, "\t")
		if !ok {
			continue
		}
		fields := strings.Fields(header)
		if len(fields) != 3 || fields[2] != "0" {
			continue
		}
		blobs[path] = fields[1]
	}
	return blobs
}

func splitNUL(output []byte) []string {
	parts := bytes.Split(output, []byte{0})
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) > 0 {
			result = append(result, string(part))
		}
	}
	return result
}

func deduplicate(findings []Finding) []Finding {
	seen := make(map[string]bool, len(findings))
	result := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		key := string(finding.Scope) + "\x00" + finding.Rule + "\x00" + finding.Path + "\x00" + finding.Revision
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, finding)
	}
	return result
}

func gitOutput(ctx context.Context, repo string, args ...string) ([]byte, error) {
	commandArgs := append([]string{"-C", repo}, args...)
	cmd := exec.CommandContext(ctx, "git", commandArgs...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err == nil {
		return output, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return nil, fmt.Errorf("git %s failed with exit code %d", args[0], exitError.ExitCode())
	}
	return nil, fmt.Errorf("run git %s: %w", args[0], err)
}
