# Agent Workstation Gateway

Agent Workstation Gateway (AWG) lets a **trusted AI or development agent** request bounded work on a user's workstation without placing the public source repository in the workstation authority path.

AWG v0.1 is security-sensitive infrastructure for trusted development workloads. It is not a malware sandbox, a remote desktop, or a safe way to execute arbitrary untrusted internet code.

## Authority model

```text
trusted agent
     |
     | strict request
     v
user-owned PRIVATE GitHub control repository
     |
     | fixed workflow + dedicated control identity
     v
narrow privileged broker
     |
     | fixed OS identity transition + policy
     v
restricted execution identity
     |
     v
explicitly approved development roots
```

The public repository contains source, schemas, documentation, tests, and disposable hosted CI. It is never the control repository for a persistent workstation runner.

## Security boundaries

- Active public workflows use only GitHub-hosted runners and read-only repository permissions.
- Installation requires a dedicated personal private control repository. Public, organization-owned, shared, or unexpectedly readable repositories fail closed in v0.1.
- Trusted control and arbitrary workload execution use separate local OS identities.
- Runner credentials, human GitHub credentials, protected gateway state, and unrelated files are unavailable to the execution identity by design and by native negative checks.
- The broker accepts only the closed execution protocol. It is not a generic root/SYSTEM shell, filesystem proxy, updater, or repository client.
- Workloads are confined to administrator-selected roots and are reaped as a native process tree on completion, timeout, stop, or broker shutdown.
- Docker and other host-powerful capabilities are not granted by the base installation.

Read the [threat model](docs/threat-model.md), [architecture](docs/architecture.md), and [ADRs](docs/adr/) before changing a boundary.

## Supported hosts

The v0.1 supported installation targets are:

- Windows x64 with dedicated non-administrator accounts and Windows services;
- Linux x64 with systemd, procfs, and POSIX ACL tools, including WSL2 distributions booted with systemd.

The Windows boundary has been exercised on an isolated native Windows host. The Linux boundary has been exercised under dedicated identities and systemd on WSL2 Ubuntu; Ubuntu, Debian, and Fedora container checks cover package names, shell assumptions, static binaries, installer planning, and ACL behavior. WSL2 and containers are not a claim of complete bare-metal coverage.

## Install

1. Download the platform archive, `awg-control_0.1.0_linux_amd64`, and `SHA256SUMS` from the [latest release](https://github.com/eldenizfamilyanskicode/agent-workstation-gateway/releases/latest). Verify every downloaded AWG asset against `SHA256SUMS` before elevation.
2. Download the exact official GitHub Actions runner package pinned in the platform guide and verify its documented size and SHA-256.
3. Authenticate the GitHub CLI as the personal account that will own the dedicated control repository: `gh auth login`.
4. Copy the platform install specification from `config/examples/v1`, choose two new synthetic/local account names, and list only intended development roots.
5. Run `awg install --dry-run --spec <path>` and inspect the complete mutation plan.
6. Run the mutating install command from an elevated Windows terminal or a root Linux shell. Use `--create-repository` to create a new dedicated private repository, or name an existing empty/private one that satisfies the exclusive-reader checks.
7. Run `awg doctor --installation-root <path>` and require every reported boundary boolean to be `true`.

Exact commands and pinned runner values are in the [Windows guide](docs/windows.md) and [Linux guide](docs/linux.md). The installer never accepts an unsafe public-repository override.

## Send work from an agent

An authorized agent creates a GitHub issue containing one strict protocol-v1 request in the dedicated private control repository, then reads the authoritative ledger result. It does not need workstation administration, runner credentials, or access to protected gateway state.

See [agent integration](docs/agents.md) for ChatGPT, Codex, Claude Code, generic GitHub-capable agents, and concise custom-instruction examples. See [protocol v1](docs/protocol-v1.md) for the exact request/result contract and [private control](docs/private-control.md) for transport semantics.

## Diagnose, update, and remove

- `awg version` prints the release version and embedded source commit.
- `awg doctor --installation-root <path>` validates installed state and remote control ownership without exposing credential contents.
- v0.1 upgrades use a fail-closed uninstall/reinstall: run `doctor`, use the matching old external release binary to uninstall, verify the new release checksums, then install the new release with the same reviewed specification and private repository. The private repository, ledger, approved-root contents, and unrelated files are preserved; execution is unavailable during the transition.
- `awg uninstall --installation-root <path>` removes only verified installer-owned services, identities, ACL grants, control files, and local roots. Drift causes a closed failure instead of broad deletion.

There is no in-place self-updater or request-driven management operation in v0.1.

## Build and verify

Go is a build dependency only; installed binaries are cgo-free and require no Go, Python, Node.js, Docker, or model runtime.

```text
gofmt -l .
go mod verify
go vet ./...
go test ./...
go test -race ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
go run ./cmd/awg-public-safety -scope all
```

Platform-specific security claims additionally require the native checks described in [CONTRIBUTING.md](CONTRIBUTING.md). Release construction and verification are documented in [docs/releasing.md](docs/releasing.md).

## Project layout

- `cmd/awg` — management and installed control CLI;
- `cmd/awg-control` — hosted private-control accept/finalize helper;
- `cmd/awg-broker` — narrow privileged service;
- `protocol/` and `runtime/` — strict public records and local broker contracts;
- `templates/control-repository/` — inert private workflow template, never active in this repository;
- `internal/platform/windows` and `internal/platform/linux` — native security boundaries.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting changes. Report vulnerabilities through the private process in [SECURITY.md](SECURITY.md); never publish real credentials or sensitive workstation data as evidence.

Licensed under the [Apache License 2.0](LICENSE).
