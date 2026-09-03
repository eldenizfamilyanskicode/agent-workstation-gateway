# Release Process

Release bytes are trusted elevated input. Follow this checklist from a trusted maintainer host; do not publish from a contributor-controlled checkout.

## Gate the source

1. Start from clean `main` with `HEAD == origin/main` and inspect the complete diff/history since the prior release.
2. Run and inspect formatting, `go mod verify`, vet, tests, Linux race tests, cgo-free cross-builds, `govulncheck`, and `awg-public-safety -scope all`.
3. Confirm the public workflow has only hosted runners, read-only permissions, full-history checkout, no secret references, and immutable action SHAs.
4. Wait for the exact `HEAD` public CI run and inspect every job/step result.

## Build

On a Linux host/container with the Go version from `go.mod`, Git, GNU tar/coreutils, `zip`, and `sha256sum`:

```bash
version=v0.1.0
source_sha=$(git rev-parse HEAD)
scripts/package-release.sh "$version" "$source_sha" "$(pwd)/dist-$version"
```

The script requires a clean tree and a new output directory. It produces only the artifacts accepted by [ADR 0022](adr/0022-v0.1-release-and-upgrade.md).

Inspect the archive member names and modes. Run both platform `awg version` binaries and `awg-control version`; each record must contain the requested tag and exact source SHA. Re-run `sha256sum --check SHA256SUMS` from the output directory.

## Publish

Create an annotated tag only after the build inspection, push it, and ensure it resolves to the gated commit:

```bash
git tag -a v0.1.0 -m "Agent Workstation Gateway v0.1.0"
git push origin v0.1.0
git rev-list -n 1 v0.1.0
```

Publish from the trusted local GitHub CLI session; the public repository deliberately has no write-authorized release workflow:

```bash
gh release create v0.1.0 dist-v0.1.0/* \
  --repo OWNER/agent-workstation-gateway \
  --verify-tag --title "Agent Workstation Gateway v0.1.0" \
  --notes-file CHANGELOG.md
```

Download the published assets into a new directory, verify them against the downloaded `SHA256SUMS`, inspect archive contents again, and confirm the release/tag source commit through the GitHub API.

## Installed release gate

Use only a separate private smoke control plane and synthetic roots/identities:

1. If upgrading a candidate, run its `doctor`, uninstall with its matching external binary, and confirm units/services, owned roots, accounts, socket/pipe, ACL grants, and runner registration are removed while the private ledger and project contents remain.
2. Install from the downloaded stable artifacts and exact official runner archive without a preinstalled Go toolchain in the execution environment.
3. Require every stable `doctor` boundary boolean and version/source field to match.
4. Execute a minimal request and inspect authoritative result, stdout/stderr, identity/capability state, credential denials, and artifacts.
5. Run stable uninstall once, inspect restoration/preservation, then reinstall and repeat `doctor` so the published release is left in a known installed state.

Record private repository names and machine-specific evidence only in the private release journal, never in public commits or release notes.

