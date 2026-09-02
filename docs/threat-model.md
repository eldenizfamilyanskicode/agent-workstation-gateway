# Threat Model

Agent Workstation Gateway (AWG) lets trusted remote agents request work on a user's real workstation through a private control plane. That capability is powerful by design. This threat model defines the boundary the implementation must preserve.

## Security stance

AWG assumes the workstation owner intentionally grants a trusted agent authority to perform development work inside explicitly approved local roots. It does **not** assume every generated command is safe. A trusted agent can make mistakes, follow malicious instructions embedded in repository content, or be compromised.

Therefore the central rule is:

> A workload may receive the authority needed for the requested development task, but it must not automatically receive authority to manage the gateway, its private control plane, the human user's credentials, or unrelated workstation data.

AWG is not a sandbox for arbitrary untrusted internet code. Commands running inside an allowed development root can still modify or delete data within the authority intentionally granted to the execution identity.

## System and trust zones

```text
UNTRUSTED / PUBLIC

public source repository
public issues / pull requests
third-party dependencies and releases
             |
             | install only after explicit trust decision
             v
TRUSTED MANAGEMENT ZONE

private control repository
control workflow
control / runner identity
runner credentials and management tokens
             |
             | authenticated request + sanitized launch
             v
RESTRICTED EXECUTION ZONE

execution identity
approved development roots
explicit optional capabilities
             |
             +------> network / external services
             |
             +------> bounded artifacts and command results
```

The public source repository is never part of the workstation control plane. A fork, public pull request, or public CI job must have no route to a persistent workstation runner.

## Protected assets

### Management authority

The highest-value assets are credentials and state that can change who controls the gateway:

- runner registration and removal credentials;
- private control-repository write credentials;
- workflow result-publication authority;
- installer/bootstrap management credentials;
- service configuration that selects trusted repositories, identities, roots, or capabilities.

A workload must not be able to read or modify these merely because it was launched by the gateway.

### Human credentials

The execution identity must not inherit access to unrelated human authentication material, including:

- interactive Git hosting credentials;
- SSH private keys;
- browser profiles and cookies;
- password-manager state;
- cloud credentials;
- unrelated application secrets.

### Filesystem data

AWG distinguishes:

1. **approved development data** — roots the owner deliberately grants to workloads;
2. **gateway/control data** — runner installation, control checkout, service state, logs, and configuration;
3. **unrelated personal or project data** — everything outside approved roots.

Only the first category is normal workload authority.

### Result integrity and auditability

Requests, results, exit codes, timestamps, artifact manifests, and source revision identifiers are security-relevant records. A workload should not be able to silently forge control-plane results or rewrite the audit trail that determines what happened.

### Availability

The gateway should resist accidental or malicious resource exhaustion where practical, but availability is secondary to credential and data isolation. Limits on time, output, artifact size/count, concurrency, and persistent processes are required safety controls.

## Trusted principals

The model trusts:

- the workstation owner;
- explicitly authorized writers to the private control repository;
- gateway management/install code after the owner chooses a trusted public source revision;
- the local operating-system security boundary when correctly configured;
- the Git hosting provider to enforce repository visibility and authentication as documented.

A remote AI agent may be trusted to request work, but its generated workload is still treated as potentially destructive within the authority granted to the execution identity.

## Threat and failure sources

The model considers:

- a malicious public contributor;
- malicious code in a public pull request;
- a compromised third-party action, dependency, download, or update channel;
- a compromised trusted-agent account;
- prompt injection or malicious instructions stored in repository content;
- an accidental but destructive agent command;
- a malicious process already present in an approved development root;
- a local process attempting to abuse gateway IPC or service permissions;
- a user misconfiguring repository visibility, roots, identities, or optional capabilities;
- symlink/reparse-point and time-of-check/time-of-use filesystem attacks;
- unexpected process inheritance, environment inheritance, or descendant escape;
- leaked secrets in logs, artifacts, requests, or results.

A fully compromised administrator/root account, operating-system kernel, firmware, or Git hosting platform can violate these assumptions and is outside the boundary AWG can independently defend.

## Entry points and control flows

### Public source installation

A user may clone or download public source. Public content is input to an installation decision, not executable control authority by itself. Active public CI must use disposable hosted runners only.

### Private control requests

Authorized actors write immutable request material to a **private** control repository. The control plane validates protocol fields and policy before launching anything locally.

### Local workload launch

The control identity launches the request through a restricted execution identity. The launch boundary must explicitly construct environment, working-directory authority, process ownership, limits, and optional capabilities.

### Artifact/result return

The workload can produce stdout, stderr, and selected files. Artifact selection is an exfiltration boundary: paths must remain inside allowed roots, be bounded, and avoid link-based escape. The control identity, not the workload, owns authoritative result publication.

### Install/update/uninstall

Management operations can create identities, ACLs, services, runner state, and private-control files. These operations require stronger authority than normal workload execution and must never be invokable merely by possessing workload privileges.

## Threat catalogue

| ID | Threat | Required mitigation direction |
|---|---|---|
| T01 | Public PR or fork reaches a persistent workstation runner | No active public workflow may target self-hosted runners. Real-host smoke is initiated only from a trusted private controller for an exact public commit. |
| T02 | User selects a public control repository | Installer verifies visibility and hard-fails. No unsafe override in the initial release. |
| T03 | Workflow environment exposes management tokens to a child process | Execution environment is constructed from an allowlist rather than inherited from the runner. |
| T04 | Workload reads runner credentials or control checkout credentials | Separate OS identities and filesystem permissions prevent execution identity access to runner/control state. Checkout credentials are not persisted unnecessarily. |
| T05 | Workload reaches human Git/SSH/browser/cloud credentials | Execution identity has a separate profile/home and no permission to human credential stores. |
| T06 | Working directory escapes approved roots | Canonicalize paths, validate ancestry, reject link/reparse escape, and enforce OS-level permissions. |
| T07 | Artifact glob exfiltrates unrelated or secret files | Artifacts are relative to an authorized root, traversal-safe, link-safe, bounded, and deny sensitive gateway locations by construction. |
| T08 | Workload forges result or audit metadata | Control identity owns final result materialization/publication; workload output is treated as data. |
| T09 | Timed-out command leaves descendants running | Platform-native process-tree/group ownership and termination; persistent processes require explicit registration. |
| T10 | Optional Docker or similar daemon access yields host-level power | Powerful capabilities are disabled by default and require explicit owner opt-in with documented implications. |
| T11 | Compromised dependency/action executes during build/install | Pin automation, verify downloaded artifacts where practical, lock dependencies, minimize bootstrap dependencies, and scan supply chain. |
| T12 | Secret is printed into logs/results during diagnostics | Presence/denial tests never print values; output paths are reviewed and bounded; docs prohibit secret dumps. |
| T13 | Symlink/reparse race changes a previously validated path | Resolve/canonicalize as close as possible to use, reject unsafe link traversal, and rely on execution-identity ACLs as the final boundary. |
| T14 | Replay/concurrency causes unintended duplicate commands | Requests have stable identities/versioning; control plane processes them idempotently with clear terminal states. |
| T15 | Workload modifies gateway service or executable | Gateway installation/configuration is owned by control/admin identities and not writable by execution identity. |
| T16 | Windows ACL or service misconfiguration collapses identity split | Doctor and installation tests verify effective access, service account, directory ACLs, and negative reads. |
| T17 | Linux sudo/systemd configuration grants broader elevation | Any helper/sudo rule is minimal and command-specific; execution identity has no general sudo/root capability. |
| T18 | Network egress exfiltrates data available to the workload | Minimize readable data first. Network restriction is a separately configurable defense and not assumed in the base threat boundary. |
| T19 | Malicious repository content prompt-injects a trusted agent | Treat generated commands as untrusted with respect to management authority; least-privilege execution limits blast radius. |
| T20 | Control repository or trusted agent credential is compromised | Compromise can authorize workloads inside configured execution authority, but must still not automatically grant gateway-management or human-account credentials. Rotate/revoke control credentials and runner registration as recovery. |

## Required security properties

These properties are release gates, not aspirational guidance.

### P1 — Public source has zero workstation authority

No public repository event, public fork, or public pull request can schedule code on the user's persistent workstation.

### P2 — Private control is mandatory

A workstation runner is registered only to a repository whose private visibility has been positively verified during bootstrap and doctor checks.

### P3 — Control and execution authority are distinct

Normal arbitrary workload does not execute with the OS identity that owns runner credentials, control checkout, result publication credentials, or gateway management files.

### P4 — Workload environment is allowlisted

The launcher creates a fresh environment containing only documented safe variables plus explicit request-scoped additions. Git hosting workflow variables, runner-management secrets, installer credentials, and unrelated human-session variables are absent.

### P5 — Filesystem access is rooted and least-privilege

Execution is permitted only inside explicitly approved development roots. OS permissions reinforce application-level path validation.

### P6 — Human credentials remain outside the execution boundary

The execution identity cannot read the human user's credential stores or private profile merely because a workload needs Git or shell access.

### P7 — Management components are not writable by workload

Runner installation, service/helper binaries, gateway configuration, control checkout, and management logs/state are not writable by the execution identity.

### P8 — Failure cannot bypass result semantics

Exit failure, timeout, invalid request, runtime failure, and artifact-publication failure remain distinguishable. Authoritative results are finalized by trusted control code.

### P9 — Process lifetime is bounded

Ordinary workload descendants die with timeout/cancellation/job completion. Persistence requires an explicit lifecycle operation with ownership metadata and later cleanup.

### P10 — Artifacts are bounded and path-safe

Artifact collection cannot use absolute paths, traversal, links, or unbounded directory selection to escape authorized data.

### P11 — Powerful capabilities are explicit

Docker, privileged local daemons, hardware access, or other host-powerful capabilities are opt-in and visible in configuration/doctor output.

### P12 — Verification proves denial without exposing secrets

Security tests check whether a resource is absent/readable/denied without printing credential contents. A passing test must be backed by inspected output from the platform actually tested.

## Security invariants for public CI

Active workflows in the public source repository must:

- run only on disposable hosted runners;
- use minimal permissions;
- avoid untrusted-code execution in privileged event contexts;
- never contain an active workstation control workflow;
- scan for accidental private identifiers, credentials, runner files, and unsafe workflow configuration.

A private control workflow may exist in the public repository only as inert template data outside the active workflow location.

## Non-goals

AWG does not promise:

- safe execution of arbitrary hostile binaries or internet malware;
- containment after the execution identity or operating-system kernel is fully compromised;
- protection of data intentionally placed inside an approved root from an authorized destructive command;
- automatic correctness of commands generated by an AI agent;
- prevention of every data exfiltration route when network access and sensitive authorized data are both intentionally granted;
- replacement of endpoint security, backups, code review, or operating-system patching.

Users should use disposable virtual machines or stronger sandboxes for truly untrusted code.

## Residual risks and assumptions

- A compromised private-control writer can intentionally request destructive work within configured execution authority.
- A vulnerable compiler, package manager, shell, or optional local tool can be exploited within the execution identity's permissions.
- Network-enabled workloads can transmit any data they are legitimately able to read. The primary defense is least-privilege readable data; optional network policy may reduce exposure later.
- Filesystem canonicalization alone is insufficient against races. OS ACL/ownership separation is required as defense in depth.
- Installation requires elevated management actions on both Windows and Linux. A malicious installer revision therefore has high impact; release/signing/update provenance matters.
- Git hosting availability and authentication are external dependencies of the default control plane.

## Verification obligations

Before a release can claim the relevant property is tested, isolated Windows and Linux smoke environments must demonstrate at least:

- public control repository rejection;
- absence of management-token variables in workload environment without printing values;
- denial reading runner/control files;
- denial reading synthetic "human secret" fixtures outside approved roots;
- allowed read/write inside the synthetic approved root;
- path/link escape denial;
- timeout descendant cleanup;
- explicit persistent-process lifecycle;
- artifact path/size/count enforcement;
- Docker denial by default and separately tested opt-in behavior if enabled;
- uninstall/reinstall without leaving credentials or overly broad permissions.

The source repository's hosted CI can validate schemas, pure policy, scanners, installers in dry-run modes, and workflow safety. It cannot substitute for isolated real-host boundary tests.

## Relationship to later decisions

This document defines **what must remain protected**. Separate architecture decisions must define **how** Windows and Linux implement the control/execution identity split, credential handling, private-control bootstrap, process isolation, and implementation runtime. Those decisions may strengthen this model but must not silently weaken these properties.
