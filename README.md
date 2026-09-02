# Agent Workstation Gateway

> **Pre-alpha:** the threat model, architecture decisions, public repository safety tooling, hosted CI, protocol v1 records, and shared execution orchestration exist. Native security boundaries, installers, private-control bootstrap, and real-host E2E implementation are still being built. Do not treat this repository as production-ready or installable yet.

Agent Workstation Gateway (AWG) is a vendor-neutral gateway for letting a **trusted AI/development agent** request bounded work on a user's workstation while keeping public source code separate from workstation execution authority.

The project targets Windows and Linux and is designed around explicit OS identities, explicit development roots, private remote authority, and a narrow privileged broker.

## What AWG is

AWG is intended to provide a reproducible path from a trusted remote agent to local development tools without requiring an inbound workstation port or giving a public GitHub repository control of the machine.

The planned v0.1 authority path is:

```text
trusted AI / development agent
            |
            | bounded request
            v
PRIVATE GitHub control repository
            |
            | fixed trusted control workflow
            v
installed AWG control component
            |
            v
narrow privileged local broker
            |
            | OS identity transition + policy
            v
restricted execution identity
            |
            v
explicitly allowed development roots
```

The public source repository is **not** in that authority chain. It contains source, documentation, schemas, tests, installers, and safe disposable CI as those pieces are implemented. A workstation installation uses a separate private control repository owned by that user.

## What AWG is not

- It is not an LLM, agent framework, or model provider.
- It is not a general remote desktop or SSH replacement.
- It is not a malware sandbox.
- It does not make arbitrary untrusted internet code safe to execute.
- A public fork or pull request must never gain an execution route to a maintainer's persistent workstation.

The remote requester is trusted to request workloads within the local authority explicitly granted to AWG. The security goal is to keep that workload authority narrower than gateway administration, operating-system administration, human credentials, and unrelated local data.

## Why a private control repository

A command request is executable authority over the configured workstation scope. For that reason, AWG's design requires a dedicated **private** control repository for normal workstation operation.

The current transport decision uses a bounded GitHub issue request in that private repository, a control-owned accepted-request ledger, a restricted self-hosted execution step, and a hosted finalization step. Requester authority is intentionally narrower than workflow, runner, repository-management, and workstation-management authority.

The bootstrap implementation will hard-fail if a selected control repository is public. The initial release will not provide an unsafe override.

## Security model

The current design requires these boundaries:

- public source has no persistent workstation runner;
- active public CI uses only disposable hosted infrastructure;
- trusted control and arbitrary workload execution use separate OS identities;
- gateway management credentials stay outside the workload environment;
- the privileged broker exposes only a bounded execution protocol, not a generic root/SYSTEM shell;
- local execution is restricted to explicitly configured development roots;
- Docker and other high-authority local capabilities are opt-in;
- Windows and Linux security behavior must be implemented and verified using native platform mechanisms before release.

See [`docs/threat-model.md`](docs/threat-model.md) and the accepted decisions in [`docs/adr/`](docs/adr/) for the detailed authority and credential model.

## Public repository safety

This public repository is designed to remain safe to inspect, fork, and contribute to without connecting contributor-controlled code to a maintainer workstation.

Active public workflows may not target `self-hosted` runners. Real hardware smoke testing, when implemented, is initiated by a separate trusted private smoke control plane against an explicitly selected public commit SHA and a synthetic workspace.

Public examples use synthetic identities and paths only. See [`SECURITY.md`](SECURITY.md), [`CONTRIBUTING.md`](CONTRIBUTING.md), and [`AGENTS.md`](AGENTS.md).

Before publication, contributors can run the project safety gate described in [docs/public-safety.md](docs/public-safety.md). It scans current/staged Git state and reachable history without connecting to a workstation control plane. The active public CI runs the same full-history gate, formatting, vet, tests, and builds on disposable GitHub-hosted Windows and Linux runners.

## Implementation direction

Security-critical product code is written in Go and packaged as self-contained native binaries where practical. The conceptual executable split is:

```text
awg          user-facing management CLI
awg-control  trusted non-privileged private-control helper
awg-broker   narrow privileged local service
```

PowerShell and POSIX shell are limited to thin bootstrap/automation responsibilities. Normal AWG operation must not require Python, Node.js, Docker, Ollama, or another language runtime merely to run the gateway.

Initial implementation targets are:

- Windows x64;
- Linux x64;
- Linux arm64.

Support claims will follow real verification rather than compiler target availability.

## Current project status

Completed foundation work:

- reference-runtime audit;
- threat model;
- control/execution identity and credential-boundary ADR;
- private-control GitHub transport ADR;
- Go runtime/packaging ADR;
- Apache-2.0 license decision;
- public security, contribution, and agent-development policies;
- local public/workflow safety scanner with reachable-history checks;
- hosted-only public CI verified on GitHub's Windows and Linux runner pools;
- strict protocol v1 request schema, Go codec/validation, canonicalization, and digest;
- strict protocol v1 accepted-request, non-authoritative execution-report, and authoritative-result schemas with provenance/binding validation and independent command/artifact outcomes;
- shared strict installation configuration, execute-only broker envelope, clean-environment builder, and fail-closed launch-policy core;
- closed shell startup plans that carry arbitrary script content only as stdin data;
- concurrent full-stream output hashing/counting with bounded retained prefixes;
- shared command lifecycle and report assembly behind mandatory native process-owner and restricted artifact-collector interfaces.

Not implemented yet at this checkpoint:

- Go CLI/control/broker executables and native IPC, identity transition, path resolution, process-tree ownership, and artifact filesystem/runtime implementation;
- Windows installer/service/ACL lifecycle;
- private control repository bootstrap;
- Windows isolated smoke lab;
- Linux/systemd implementation and smoke tests;
- release/update/uninstall hardening.

The README will be updated as those capabilities become real and verified.

The implemented protocol v1 contracts are documented in [`docs/protocol-v1.md`](docs/protocol-v1.md).

The implemented shared policy boundary and its explicit native gaps are documented in [`docs/architecture.md`](docs/architecture.md).

## Architecture decisions

- [`ADR 0001 — Control/Execution Identity and Credentials`](docs/adr/0001-control-execution-identity-and-credentials.md)
- [`ADR 0002 — Private Control Repository and GitHub Transport`](docs/adr/0002-private-control-repository-and-github-transport.md)
- [`ADR 0003 — Go Runtime and Packaging`](docs/adr/0003-go-runtime-and-packaging.md)
- [`ADR 0004 — Apache License 2.0`](docs/adr/0004-apache-2.0-license.md)

## Contributing and security

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before submitting changes. Security reports should follow [`SECURITY.md`](SECURITY.md) and should never publish real credentials or sensitive workstation data merely to demonstrate impact.

## License

Licensed under the [Apache License 2.0](LICENSE).
