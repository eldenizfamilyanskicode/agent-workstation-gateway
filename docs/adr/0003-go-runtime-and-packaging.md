# ADR 0003 — Go Runtime and Cross-Platform Packaging

- Status: Accepted; v0.1 artifact matrix superseded in part by ADR 0022
- Date: 2026-09-02
- Scope: implementation language, executable layout, platform-specific native integration, and distribution model

## Context

Agent Workstation Gateway (AWG) needs a small security-critical implementation that can run as a Windows service, a Linux system service, a command-line management tool, and a trusted control helper without requiring a language runtime to already exist on the user's workstation.

The implementation must preserve the boundaries established by the threat model and earlier ADRs:

- public source has no workstation authority;
- the private control repository is distinct from public source;
- arbitrary workload runs under a restricted execution identity;
- a narrow privileged broker performs the OS identity transition;
- the broker receives no GitHub credential and exposes no generic privileged shell;
- Windows and Linux are first-class targets rather than one platform being a translation layer for the other.

The language choice therefore affects the attack surface, installer complexity, supply-chain surface, native API fidelity, release packaging, and the ability to test the same core protocol on both platforms.

## Decision

AWG v0.1 uses **Go** for the security-critical product implementation.

One Go module contains shared protocol/domain packages plus platform-specific implementations selected by build tags. The initial executable layout is conceptually:

```text
awg
    user-facing CLI and local management commands

awg-broker
    privileged local service
    Windows: LocalSystem service
    Linux: root systemd service

awg-control
    trusted non-privileged control helper used by the private control workflow
```

The exact package boundaries may evolve during implementation, but privilege boundaries may not be collapsed merely to reduce the executable count.

PowerShell on Windows and POSIX shell on Linux may be used for **thin bootstrap wrappers** where native installation UX requires them. Shell scripts do not implement the privileged execution protocol, request validation, identity transition, credential isolation, artifact policy, or authoritative process lifecycle.

Normal AWG use must not require Python, Node.js, npm, uv, PowerShell modules, a C compiler, or another language runtime to be installed for the product binaries themselves.

## Why Go

### Self-contained distribution

For the design used by AWG, Go can produce native executables without shipping an interpreter beside the application. Pure-Go cross-compilation directly supports Windows and Linux targets through `GOOS` and `GOARCH`; cgo is disabled by default when cross-compiling.

The base product therefore targets binaries such as:

```text
windows/amd64
linux/amd64
linux/arm64
```

Windows arm64 is technically supported by the Go toolchain and can be added when the project has a real verification environment for it. Support claims follow tested platforms, not merely compiler target availability.

AWG should keep the base runtime **cgo-free** unless a later ADR demonstrates a specific requirement. Avoiding cgo reduces native build-toolchain and dynamic-library coupling and keeps cross-platform release builds simpler. A future dependency that requires cgo is a packaging/security decision, not a casual implementation detail.

### Windows native boundary

The Go project-maintained `golang.org/x/sys/windows` package exposes low-level Windows APIs needed by ADR 0001, including process/token and service-related primitives. `golang.org/x/sys/windows/svc` is specifically designed for implementing Windows services.

Platform-specific Go code can therefore wrap and narrowly expose the required operations for:

- service lifecycle;
- Windows access tokens;
- `LogonUserW` / batch-logon flow;
- `CreateProcessAsUserW`;
- explicit process environment construction;
- named pipes and peer authorization;
- security descriptors / ACL work;
- job/process-tree lifecycle;
- DPAPI-backed broker state where required.

Raw native handles and unsafe boundary details stay inside small Windows-only packages. Higher-level protocol and policy code does not manipulate them directly.

### Linux native boundary

Go's process APIs and `golang.org/x/sys/unix` expose the Linux primitives needed by the chosen design, including:

- UID/GID and supplementary-group operations;
- process groups and sessions;
- Unix-domain sockets;
- peer credentials such as `SO_PEERCRED`;
- `prctl` constants/operations including no-new-privileges;
- signals and process lifecycle;
- filesystem ownership and permission primitives.

Linux implementation remains native Linux code behind platform-specific files. The project does not emulate Linux behavior with PowerShell or require Docker to run the gateway.

### Typed privileged core

The privileged broker is a high-impact component. Go provides memory safety for ordinary code while remaining close enough to native OS APIs to implement the boundary directly. The project should minimize explicit `unsafe` usage; where possible it should rely on the maintained `x/sys` wrappers and contain unavoidable native marshalling in small reviewed packages.

Go does not make a privileged broker automatically secure. Parser bounds, IPC authentication, filesystem policy, process lifetime, secret handling, and negative tests remain mandatory. The language choice only reduces some classes of implementation risk and packaging complexity.

### Dependency and vulnerability management

The repository commits both `go.mod` and `go.sum`. Dependencies must remain deliberately small, and standard-library / `golang.org/x/sys` capabilities are preferred over broad frameworks when practical.

Go module checksums provide integrity verification for downloaded module content. Public CI and release hardening should include `govulncheck` so known reachable vulnerabilities in Go code/dependencies are surfaced using the Go vulnerability database.

This does not replace dependency review, release provenance, pinned Actions, or verification of externally downloaded tools such as the GitHub runner.

## Package architecture

The preferred source shape is approximately:

```text
cmd/
  awg/
  awg-broker/
  awg-control/

internal/
  protocol/
  policy/
  execution/
  artifacts/
  process/
  platform/
    windows/
    linux/
```

This is a direction, not a requirement to create every directory immediately.

Shared packages own platform-neutral concepts such as:

- request/result models;
- canonicalization and validation;
- bounded output metadata;
- artifact-policy models;
- status/failure semantics;
- local control protocol types.

Platform packages own OS mechanisms such as:

- account/token/UID transitions;
- local IPC creation and peer identity checks;
- service integration;
- process-tree/group termination;
- ACL/ownership behavior;
- platform-specific path/link handling.

A shared interface must not erase meaningful Windows/Linux security differences. Abstraction exists to share invariants, not to force both platforms through the same lowest-common-denominator implementation.

## Privileged broker constraints

The broker is intentionally small.

It must not gain features merely because Go makes them easy to add. In particular it must not become:

- a generic root/SYSTEM command server;
- an arbitrary run-as-user API;
- a filesystem proxy for privileged reads;
- a repository client;
- a GitHub client;
- an updater driven by normal requester data;
- a general account/ACL/service-management daemon.

Administrative installation/update/repair remains a separate elevated management path. The normal broker IPC only implements the bounded AWG execution protocol.

## CLI and control helper

The `awg` CLI owns user-facing management and diagnostics. Commands that require elevation must make that transition explicitly through platform installation mechanisms rather than assuming every CLI invocation runs as administrator/root.

The `awg-control` helper runs under the dedicated control/runner identity. It parses already accepted data from the fixed private workflow, speaks the authenticated local broker protocol, and returns bounded result data. It has no reason to execute arbitrary workload as its own OS identity.

Keeping the control helper as compiled trusted code also means the fixed private workflow does not need to download or execute mutable repository scripts for normal requests.

## Bootstrap scripts

A small Windows bootstrap may be PowerShell and a small Linux bootstrap may be POSIX shell.

They may:

- detect platform/architecture;
- download a selected signed/checksummed release artifact;
- verify a published digest/signature according to the later release design;
- invoke the compiled installer/CLI with explicit arguments;
- print actionable errors.

They must not contain the security-critical broker policy or act as a long-lived privileged runtime.

Avoid `curl | sh` style installation as the primary documented path. If a convenience bootstrap is ever provided, downloaded bytes are verified before privileged execution.

## Build and release model

Release builds should be reproducible from a pinned Go toolchain/module graph as far as practical.

Required release artifacts initially include at least:

```text
awg_<version>_windows_amd64.zip
awg_<version>_linux_amd64.tar.gz
awg_<version>_linux_arm64.tar.gz
SHA256SUMS
```

The archives contain the relevant product binaries plus license/notices and any inert install assets needed by that platform. They do not bundle a private control repository, machine configuration, credentials, or a GitHub runner registration token.

Version information and source commit should be embedded in the binaries at build time so `awg version` and `doctor` can report exactly what is installed. Release signing/provenance is decided during release-hardening work, but the packaging layout must allow signature verification before installation/update.

## Testing implications

The choice of a cross-platform language does not reduce the real-host test matrix.

Public disposable CI should build and unit-test supported targets. Platform-specific behavior is verified on the actual platform:

- Windows process tokens, service behavior, ACLs, named-pipe authorization, and process-tree semantics on Windows;
- UID/GID/groups, systemd, Unix socket peer credentials, symlinks, signals, and process groups on Linux/WSL2;
- Docker remains useful only for cross-distribution Linux compatibility tests.

Cross-compiling a binary is evidence that it builds, not evidence that the platform security boundary works.

## Alternatives considered

### Rust

Rust is the strongest rejected alternative and remains a credible future reconsideration.

Advantages:

- memory safety without garbage collection;
- excellent FFI/native-system capabilities;
- self-contained native binaries;
- fine control over data ownership and sensitive buffers.

Reasons not selected for v0.1:

- higher implementation/toolchain complexity for this project's contributor profile;
- more friction around cross-target native Windows/Linux dependency combinations when crates introduce native requirements;
- the required AWG boundary can already be implemented in Go using maintained OS wrappers with a smaller initial engineering burden.

Rust is **not** rejected as insecure. If future broker requirements demand tighter control over memory layout/zeroization or Go's runtime/native integration becomes a concrete limitation, this ADR should be revisited with measured evidence.

### Python

Rejected for the privileged product runtime.

Python is excellent for rapid application development and tests, but a normal AWG installation would need to provide or depend on an interpreter environment. Windows' embeddable Python distribution still ships the interpreter/DLL and standard-library payload as application components. That increases installation/update/dependency surface for a service whose primary job is narrow native privilege mediation.

Python may still be used for development tooling only when justified; project Python tooling must use `uv`. Python is never a runtime requirement for executing AWG workloads unless the user independently chooses Python as a workstation capability.

### PowerShell + Bash implementation

Rejected for the core runtime.

Platform shells are valuable installation and diagnostic tools, but making them the privileged broker/control implementation would:

- split core behavior across two dynamic-language implementations;
- increase dependence on host shell versions/modules;
- make protocol/parser and native-handle logic harder to keep structurally aligned;
- encourage privileged policy to drift into scripts.

Thin wrappers remain allowed as described above.

### C or C++

Rejected for the privileged core because the project does not need to accept the additional memory-safety burden to obtain the required OS APIs. Native APIs remain reachable through Go's maintained system packages.

### Mixed Go + Rust privileged components

Not selected initially. Two compiled ecosystems would increase build, dependency, audit, packaging, and contributor complexity before a concrete need exists. Prefer one typed compiled core until evidence justifies a split.

## Consequences

### Benefits

- one primary implementation language across Windows and Linux;
- native self-contained product binaries;
- no interpreter dependency for normal installation/use;
- maintained access to required Windows and Linux system primitives;
- relatively simple cross-compilation for cgo-free code;
- narrow typed privileged broker implementation;
- straightforward module checksum and vulnerability tooling;
- easier reuse of protocol/policy code between platforms without erasing OS-specific security code.

### Costs and risks

- garbage collection means sensitive plaintext lifetime cannot be reasoned about as precisely as in Rust; secret-bearing buffers still require narrow handling and explicit zeroing where APIs permit it;
- some Windows system calls ultimately involve unsafe/native marshalling under wrappers;
- Go binaries are larger than minimal native C/Rust programs;
- a single language can tempt over-abstraction across Windows/Linux; code review must preserve platform-specific invariants;
- cgo-free remains a design constraint that must be re-evaluated deliberately if a necessary dependency conflicts with it.

## Verification requirements

This ADR is an implementation choice, not evidence that the implementation exists.

Before release, evidence must demonstrate at least:

- cgo-free release builds for the claimed target matrix;
- version/source metadata embedded in built artifacts;
- `govulncheck` and module-integrity checks in public CI/release hardening;
- actual Windows service + token/process boundary tests;
- actual Linux systemd + UID/GID/socket/process boundary tests;
- installer operation on a machine without a preinstalled Go toolchain;
- execution workloads working without inheriting or requiring the gateway's build toolchain;
- published release artifacts matching documented checksums/provenance.

## References

Primary references reviewed for this decision:

- Go — Installing Go from source / supported `GOOS` and `GOARCH`: https://go.dev/doc/install/source
- Go Wiki — Building Windows Go programs on Linux: https://go.dev/wiki/WindowsCrossCompiling
- Go Packages — `golang.org/x/sys`: https://pkg.go.dev/golang.org/x/sys
- Go Packages — Windows services: https://pkg.go.dev/golang.org/x/sys/windows/svc
- Go Packages — Unix system interfaces: https://pkg.go.dev/golang.org/x/sys/unix
- Go Packages — `syscall.SysProcAttr`: https://pkg.go.dev/syscall#SysProcAttr
- Go — Vulnerability management: https://go.dev/doc/security/vuln/
- Go Wiki — Modules and checksum behavior: https://go.dev/wiki/Modules
- Python — Windows embeddable distribution: https://docs.python.org/3/using/windows.html
- Python — Windows embedding FAQ: https://docs.python.org/3/faq/windows.html
- Rust Cargo — `cargo build` target selection: https://doc.rust-lang.org/cargo/commands/cargo-build.html

## Follow-up decisions

Protocol schemas remain a separate Phase 2 concern. Installer/ACL/service layout, exact process-tree mechanics, local IPC message format, release signing/provenance, and update/rollback behavior are implemented and verified in later bounded work units.

Those later decisions may refine package/executable boundaries, but they must not turn Python/Node/shell into a hidden core runtime dependency, move normal workload execution into the control identity, or collapse the privileged broker into a generic privileged command service.
