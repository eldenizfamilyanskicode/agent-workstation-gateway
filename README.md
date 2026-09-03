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
- Windows handle-based working-directory resolution with final-path/link-escape rejection (without ACL or process-launch claims).
- Windows mandatory-token `CreateProcessAsUserW` and Job Object process-tree implementation (without installed-account/service E2E claims).
- Windows machine-protected credential file and fixed-account batch-logon/profile token source (without installer-created-account success claims).
- strict Windows install specification, mutation-free `awg install --dry-run`, and native protected broker-state materializer (not yet wired to mutating account/service installation).
- create-new Windows control/execution account transaction with crypto-random credentials, Users-only policy, fixed LSA logon rights, SID binding, and owned rollback (mutating path reserved for isolated elevated verification).
- rollback-capable Windows approved-root/profile/temp ACL convergence with same-handle validation and exact restricted execution rights (installed-account effective access reserved for isolated verification).
- fixed Windows named-pipe transport with first-instance/local-only policy, exact protected DACL verification, bounded framing, and exact impersonated control-SID authentication (installed-account and remote-host evidence reserved for isolated verification).
- Windows artifact collection under exact execution-token impersonation with portable bounded globs, link/final-path enforcement, stable content handles, and explicit omissions (broker upload and installed-token evidence remain).
- strict one-exchange broker response streaming with canonical reports, bounded retained output, stable artifact-handle chunks, end-to-end length/digest checks, and transactional receiver cleanup (hosted upload remains).
- one-request broker session orchestration with immutable installed policy, authorize-before-run ordering, coarse failures, fixed I/O deadlines, report rebinding, and authenticated Windows pipe integration using fake execution internals (installed-identity evidence remains).
- Windows broker startup composition from exact protected fixed state, native-only system-directory facts, execution-authority separation, real launcher/collector/session dependencies, and owned one-connection lifecycle (installed-identity E2E remains).
- service-only Windows `awg-broker` executable with exact LocalSystem/SCM gates, deterministic stop/shutdown ownership, and a closed per-connection retry policy (installed-host E2E remains).
- fixed create-new Windows broker-service registration with minimal SCM rights, disabled security-first staging, exact LocalSystem/Administrators service ACL, bounded recovery, independent verification, and create-owned rollback (elevated isolated-host evidence remains).
- create-new Windows installer transaction composing account/SID, workload ACL, protected root/image/state, execution-secret clearing, and fixed service leases under reverse rollback (not yet exposed by the CLI or elevated-smoke verified).
- bounded Windows `awg execute-local` control client with exact envelope/report/attempt binding and create-new atomic response-directory publication (installed identity, runner, and hosted finalization evidence remain).

Not implemented yet at this checkpoint:

- hosted result finalization, persistent attempt state, Linux native IPC/artifact implementation, and remaining installed-host integration;
- Windows installer CLI/runner composition, service start/integration, and uninstall lifecycle;
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
- [`ADR 0005 — Windows Native Path Resolution`](docs/adr/0005-windows-native-path-resolution.md)
- [`ADR 0006 — Windows Restricted Process and Job Boundary`](docs/adr/0006-windows-restricted-process-and-job-boundary.md)
- [`ADR 0007 — Windows Protected Batch Token Source`](docs/adr/0007-windows-protected-batch-token-source.md)
- [`ADR 0008 — Windows Local Account and Logon-Right Provisioning`](docs/adr/0008-windows-local-account-and-logon-right-provisioning.md)
- [`ADR 0009 — Windows Workload Filesystem ACLs`](docs/adr/0009-windows-workload-filesystem-acls.md)
- [`ADR 0010 — Windows Authenticated Named-Pipe IPC`](docs/adr/0010-windows-authenticated-named-pipe.md)
- [`ADR 0011 — Windows Artifacts Under Execution Authority`](docs/adr/0011-windows-execution-authority-artifacts.md)
- [`ADR 0012 — Bounded Local Broker Response Stream`](docs/adr/0012-bounded-local-broker-response-stream.md)
- [`ADR 0013 — Bounded Broker Session Orchestration`](docs/adr/0013-bounded-broker-session-orchestration.md)
- [`ADR 0014 — Windows Broker Startup Composition`](docs/adr/0014-windows-broker-startup-composition.md)
- [`ADR 0015 — Windows SCM Broker Service Lifecycle`](docs/adr/0015-windows-scm-broker-service.md)
- [`ADR 0016 — Windows Broker Service Registration`](docs/adr/0016-windows-broker-service-registration.md)
- [`ADR 0017 — Windows Create-New Installer Transaction`](docs/adr/0017-windows-create-new-installer-transaction.md)
- [`ADR 0018 — Windows Control Client Response Publication`](docs/adr/0018-windows-control-client-response-publication.md)

## Contributing and security

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before submitting changes. Security reports should follow [`SECURITY.md`](SECURITY.md) and should never publish real credentials or sensitive workstation data merely to demonstrate impact.

## License

Licensed under the [Apache License 2.0](LICENSE).
