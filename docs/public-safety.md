# Public Safety Scanner

`awg-public-safety` is the repository-side safety gate used before AWG activates public CI or publishes security-sensitive changes. It is intentionally independent of workstation execution: it only inspects Git state and files.

## Run it

From the repository root:

```text
go run ./cmd/awg-public-safety -scope all
```

Supported scopes are:

- `current` — tracked files in the current working tree;
- `staged` — added/modified/renamed files in the Git index;
- `history` — every commit reachable from `git rev-list --all`, including commit metadata and historical blobs;
- `all` — current, staged, and history checks together.

The command exits `0` when clean, `1` when findings exist, and `2` for invalid configuration or scanner/runtime errors.

## Ephemeral private patterns

Machine-specific paths, private repository names, and other operator-only identifiers must not be committed merely so the public scanner can detect them. Supply them at invocation time instead.

The command reads newline-separated literals from `AWG_PUBLIC_SAFETY_FORBIDDEN` and newline-separated Go regular expressions from `AWG_PUBLIC_SAFETY_FORBIDDEN_REGEX`. It clears both variables inside the scanner process before invoking Git and never prints matched values.

PowerShell example using a synthetic marker:

```text
$env:AWG_PUBLIC_SAFETY_FORBIDDEN = 'SYNTHETIC-LOCAL-MARKER'
go run ./cmd/awg-public-safety -scope all
Remove-Item Env:AWG_PUBLIC_SAFETY_FORBIDDEN
```

POSIX shell example:

```text
AWG_PUBLIC_SAFETY_FORBIDDEN='SYNTHETIC-LOCAL-MARKER' \
  go run ./cmd/awg-public-safety -scope all
```

For sensitive real values, prefer invoking an already-built scanner binary so build tools do not inherit those environment values. Environment variables can still be observable by same-user processes on some operating systems; use this feature only on a trusted development host.

## What it checks

The scanner currently fails closed on:

- AWG private runtime request/result residue and runner credential/state filenames;
- environment-secret files and selected credential-container filenames;
- high-confidence private-key and GitHub token forms;
- operator-provided literal/regex matches in paths, file contents, and reachable commit metadata;
- active `.github/workflows/*.yml` or `.yaml` files containing a `self-hosted` runner route;
- active public workflow files containing a `pull_request_target` trigger;
- tracked or historical blobs larger than 8 MiB, because they are not silently skipped.

Tracked symlinks are inspected as link targets rather than followed into the host filesystem.

## Deliberate limitations

This is a project-specific publication gate, not a comprehensive secret scanner. It does not claim to recognize every credential format or private identifier. The `current` scope scans tracked files, not arbitrary untracked files. Workflow checks are deliberately conservative and may reject forbidden tokens even when they appear only in comments inside an active workflow file.

Do not weaken a rule simply to make a scan green. Remove prohibited material from reachable public history or document and fix a genuine scanner defect before publication.