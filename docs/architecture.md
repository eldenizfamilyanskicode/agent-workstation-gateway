# Secure Execution Architecture

This document describes the implemented shared execution-policy/lifecycle core and the native Windows/Linux mechanisms still required before Agent Workstation Gateway can execute a request securely. The repository remains pre-alpha and does not yet contain a usable broker service.

## Authority path

AWG keeps request authority, control-plane authority, privileged mediation, and workload authority in different roles:

```text
remote requester
  |
  | bounded protocol v1 request
  v
private hosted accept job
  |
  | create-once accepted.json
  v
dedicated control identity
  |
  | execute-only local envelope
  v
privileged native broker
  |
  | fixed identity transition + protected policy
  v
dedicated execution identity
  |
  v
explicit approved development root
```

The public source repository is not part of this live authority path. Its active workflows use disposable GitHub-hosted runners only.

## Administrator-owned installation configuration

The implemented Go contract is in [`internal/installconfig`](../internal/installconfig). Its machine-readable schema and synthetic examples are under [`config`](../config).

The configuration is strict, versioned JSON with a 65,536-byte encoded limit. Every field is required, field names are exact and case-sensitive, nested duplicate/unknown fields are rejected, and no implicit defaults are introduced while decoding.

| Field | Authority and invariant |
|---|---|
| `config_version` | Exactly `1`. |
| `platform` | Closed to `windows` or `linux`. |
| `control_identity` | Fixed logical name plus Windows user/primary-group SIDs or non-root Linux UID/GID identifiers. |
| `execution_identity` | Different fixed user identity plus its fixed primary group; never request-selectable. |
| `approved_roots` | One to sixteen canonical absolute non-filesystem-root paths, with duplicate/nested overlaps rejected. |
| `shells` | One to five platform-compatible protocol shells bound to protected absolute executable paths. |
| `profile_root` / `temp_root` | Dedicated execution state paths that may not overlap an approved development root. |
| `path_entries` | Explicit protected absolute tool directories; inherited caller `PATH` is not used. |
| `capabilities` | Closed explicit capability grants. The base examples use `[]`. |

Configured shell executables and PATH entries may not reside inside an approved root, because the workload can modify files in that root. Windows drive letters use canonical uppercase form. Linux user/group IDs reject root and the invalid all-ones UID/GID value.

The only currently declared optional powerful capability is `docker`. Merely listing it does not implement or enable Docker access. A later elevated installer must ask explicitly, apply native membership/permissions, expose the grant in `doctor`, and document that common Docker daemon access is host-powerful. A normal execute request cannot change this array.

The decoder validates configuration content. It does not prove file ownership or permissions. Native installation/service startup must load it from protected administrator-owned storage that neither control nor execution identity can modify.

## Windows installation planning and protected state

[`internal/installplan`](../internal/installplan) defines a strict pre-SID Windows install specification and deterministic plan. The user supplies account names and workstation paths, but not resolved SIDs, credential locations, service commands, or arbitrary privileged actions. It rejects an installation root that is non-canonical, a filesystem root, or overlaps approved/profile/temp workload authority.

`awg install --dry-run` is currently the only enabled install command. It reads the bounded specification and prints the fixed plan without generating a credential or performing mutation.

[`internal/installstate`](../internal/installstate) binds native-resolved SIDs into the strict installed configuration and orders protected writes. The Windows implementation uses explicit LocalSystem/Administrators-only protected descriptors, same-handle final-path/type checks, bounded write-through replacement, and post-write owner/DACL verification. It seals only a private password copy and writes `installation.json` after the credential blob. [Windows implementation documentation](windows.md) describes the layout and evidence limits.

[`internal/accountprovision`](../internal/accountprovision) owns the create-new identity transaction. The native Windows implementation is closed to the two validated account names, Users-only membership, and fixed service/batch plus deny-logon right sets. A lease carries generated credentials only into subsequent local installation steps, tracks partial NetAPI success for rollback, and clears credentials on commit/close. [ADR 0008](adr/0008-windows-local-account-and-logon-right-provisioning.md) records why existing accounts are not implicitly adopted.

[`internal/filesystemprovision`](../internal/filesystemprovision) owns the workload-filesystem transaction. Its Windows backend is constructed from the installed configuration, so native calls cannot expand the target path/SID set. Approved roots retain their existing owner, DACL-protection state, and non-execution principals while receiving exactly one inheritable execution Modify ACE. Dedicated profile/temp roots receive a protected System/Administrators/execution DACL. Same-handle path/descriptor checks, reverse rollback, and transaction-created-leaf ownership are described in [ADR 0009](adr/0009-windows-workload-filesystem-acls.md). The operation does not recursively override protected descendants; effective installed-token access remains a `doctor` and isolated-smoke requirement.

## Execute-only local broker envelope

The local envelope contract is implemented in [`internal/brokerproto`](../internal/brokerproto), with a schema/example under [`runtime`](../runtime). It contains exactly:

```text
protocol_version
operation = execute
attempt_id
accepted_request
```

The embedded record must pass the complete protocol v1 accepted-request validation, including canonical request digest binding. The encoded envelope is limited to 147,456 bytes.

There are no fields or operations for:

- selecting a run-as identity;
- inheriting or adding environment variables;
- changing approved roots or capabilities;
- arbitrary privileged filesystem reads;
- account, group, ACL, service, runner, repository, workflow, or secret management;
- installation, update, repair, or uninstall.

Those names are rejected as unknown data. Administrative lifecycle operations remain local elevated CLI/installer actions and must not be added to the runner-facing endpoint.

The envelope contract does not authenticate a caller by itself. On Windows, [`internal/platform/windows/brokeripc`](../internal/platform/windows/brokeripc) supplies the implemented fixed named-pipe boundary: an exact protected DACL, first-instance/local-only modes, a fixed authentication preface, and exact impersonated TokenUser SID authorization before it exposes framed envelope bytes. [ADR 0010](adr/0010-windows-authenticated-named-pipe.md) records the details and evidence limits. The Linux Unix-socket peer boundary remains unimplemented.

## Shared launch authorization

[`internal/executionpolicy`](../internal/executionpolicy) builds an immutable launch plan through this sequence:

1. revalidate the protected installation configuration;
2. revalidate the complete execute envelope and accepted-request digest;
3. require the request path form to match the installed platform;
4. bind the requested shell enum to its administrator-configured executable;
5. pass the requested working directory and a copy of approved roots to a required native resolver;
6. reject resolver errors, request mismatch, invalid canonical results, unconfigured roots, and results outside the selected root;
7. build a fresh allowlisted workload environment;
8. copy request artifact selections and configured capabilities into a launch plan to avoid caller slice mutation.

The resulting plan always names the configured execution identity. It never contains the control identity as a choice and exposes no general executable or identity selector from request data. The script remains arbitrary workload data and only becomes executable after the native broker completes the fixed identity transition.

## Clean workload environment

[`internal/workloadenv`](../internal/workloadenv) never calls `os.Environ` and never copies an inherited caller environment wholesale.

It constructs deterministic `key=value` entries from:

- protected profile, temp, PATH, and execution-identity configuration;
- validated request/session/attempt identifiers;
- a very small projection of an execution-user environment block supplied by the native launcher.

Windows may project only validated system facts such as `SystemRoot`, `WINDIR`, `PATHEXT`, OS, and processor descriptors. `SystemRoot` and `WINDIR` are required, canonical absolute paths, and must agree. Linux may project only validated `LANG`, `LC_ALL`, and `TZ` values.

The builder then supplies gateway-owned values such as `HOME`, platform temp variables, `PATH`, the execution account name, and bounded `AWG_*` identifiers. Input order does not affect output order.

Everything else is dropped, including GitHub/Actions, runner, cloud, SSH-agent, Git credential, human-session, and arbitrary caller variables. Tests use synthetic marker values and assert only name/value absence; they do not print real secrets.

## Native filesystem resolver contract

The shared code deliberately does not implement filesystem authorization with lexical prefix checks alone. [`internal/platformpath`](../internal/platformpath) removes avoidable syntax aliases and provides segment-aware comparison, but it cannot detect links, reparse points, mount changes, or filesystem races.

The launch policy therefore requires a native resolver. Its contract is to:

- resolve/canonicalize the requested working directory as close as possible to launch;
- prove the resolved directory is under one configured resolved root;
- reject Windows reparse/link escape or Linux symlink escape according to native rules;
- return the exact request it evaluated plus canonical working/root paths;
- fail closed on absence, access errors, ambiguous paths, and policy races it cannot safely handle.

The shared policy independently checks that returned paths are canonical, that the root is configured, and that the directory is segment-contained. A mock resolver proves only shared orchestration behavior.

The Windows implementation in [`internal/platform/windows/pathresolver`](../internal/platform/windows/pathresolver) opens real directory handles and uses `GetFinalPathNameByHandleW`. It rejects a configured root that natively aliases another path and rejects a requested directory whose final path escapes every configured root. Local and hosted Windows tests exercise real directories and a real symbolic-link/reparse escape. [ADR 0005](adr/0005-windows-native-path-resolution.md) records the native dependency and the residual pathname race.

This resolver is not an ACL sandbox and does not eliminate replacement between resolution and process creation. The Windows launcher must repeat the check near launch, protected ACLs must deny unrelated data, and native artifact reads need their own handle-based containment. The Linux resolver is still unimplemented.

## Closed shell invocation and shared lifecycle

[`internal/shellinvoke`](../internal/shellinvoke) maps only the five protocol shell values to fixed startup argument vectors. Bash variants use `--noprofile --norc -s`, PowerShell variants use `-NoLogo -NoProfile -NonInteractive -Command -`, and `cmd.exe` uses `/D /Q`. In every case, the arbitrary requester script is exposed to the native launcher only as stdin data. It is never concatenated into a trusted command string, executable path, or argument.

[`internal/executionrun`](../internal/executionrun) orchestrates an authorized plan, but deliberately has no `os/exec` fallback. Its required launcher interface must start under the fixed execution identity and own the complete native process tree. A normal exit signal means that tree has been reaped; timeout or cancellation calls synchronous whole-tree termination. Failure to terminate is reported as `runtime_failed`, and artifact collection is skipped because the workload may still be live.

The shared runner distinguishes completed, nonzero exit, runtime failure, timeout, and cancellation. [`internal/outputcapture`](../internal/outputcapture) concurrently hashes and counts every observed stdout/stderr byte while retaining only the accepted per-stream prefix. Returned retained byte slices are separate from the execution-report metadata and are never embedded in the durable ledger record.

Artifact collection is a separate injected native boundary. Its plan contains only the fixed execution identity, resolved working directory, and accepted selections—not the script, shell arguments, or environment. Collector failure becomes explicit `collection_failed` omissions without overwriting the command outcome. The lifecycle now couples validated manifest entries to a closeable content bundle and rejects files not matched by their accepted group patterns.

The Windows implementation in [`internal/platform/windows/artifact`](../internal/platform/windows/artifact) enumerates and opens under an independently validated execution token, rejects sensitive/reparse/hard-link/alias/type escapes, enforces fixed scan/depth/file/byte limits, and hashes through stable handles that deny conflicting write/delete opens until streamed or closed. [ADR 0011](adr/0011-windows-execution-authority-artifacts.md) records the exact policy. The entire Linux collector remains unimplemented.

[`internal/brokerwire`](../internal/brokerwire) implements the one-exchange response stream over the bounded IPC frames. A strict preamble distinguishes execution from a coarse closed rejection. Execution then carries the canonical report, retained stdout/stderr in 64 KiB chunks, and artifact handle content in manifest order. Retained prefixes and every artifact are length- and SHA-256-checked. A fixed terminal/ack handshake lets the Windows server close only after the client consumed the stream; the client still requires EOF before committing its artifact transaction. The broker never receives a destination path, and the wire record cannot claim hosted finalization authority. [ADR 0012](adr/0012-bounded-local-broker-response-stream.md) records the sequence and cleanup contract.

[`internal/brokersession`](../internal/brokersession) now composes one already-authenticated connection through bounded frame read, strict envelope decode, installed-policy authorization, the shared execution lifecycle, independent accepted-request/attempt/source binding, and one terminal wire exchange. It owns copied configuration/environment inputs and fixed request/write/ack deadlines; rejected data maps only to coarse codes. The Windows named-pipe connection exposes context-aware overlapped I/O so a stalled authenticated peer is bounded. [ADR 0013](adr/0013-bounded-broker-session-orchestration.md) records the state machine.

[`internal/platform/windows/brokerhost`](../internal/platform/windows/brokerhost) is the real Windows dependency composition root. From one canonical installation root it derives fixed protected configuration/credential paths, rejects any overlap with execution-owned roots, obtains only `SystemRoot`/`WINDIR` from the native system-directory API, and constructs the fixed token source, launcher, artifact collector, resolver, runner, session, and authenticated listener without current-user fallbacks. Each accepted connection is always closed after one session. [ADR 0014](adr/0014-windows-broker-startup-composition.md) records startup ordering and evidence limits.

[`internal/controlclient`](../internal/controlclient) and [`internal/platform/windows/controlresponse`](../internal/platform/windows/controlresponse) implement the non-privileged client side. One canonical envelope is sent to the fixed pipe, the acknowledged response is staged into create-new paths, accepted-request and attempt binding is checked, and the entire local response directory is exposed with one same-parent rename. Windows-reserved names, case aliases, reparse parents, and existing/racing final paths are denied. `awg execute-local` exposes this boundary without accepting broker policy or printing decoded request content. [ADR 0018](adr/0018-windows-control-client-response-publication.md) records why brokerwire artifact commit remains staging-only until outer binding passes. Persistent attempt state and hosted upload remain unimplemented.

[`internal/platform/windows/brokerservice`](../internal/platform/windows/brokerservice) and the service-only [`cmd/awg-broker`](../cmd/awg-broker) provide the SCM lifecycle. Startup requires a real SCM context, exact LocalSystem TokenUser, one canonical administrator-controlled installation root, and a build-embedded lowercase source SHA. Stop/shutdown cancellation closes both listener and active connection before waiting for the sequential broker loop. Only closed peer/session failures are retried; listener infrastructure and connection-close failures are terminal. [ADR 0015](adr/0015-windows-scm-broker-service.md) records this boundary.

[`internal/platform/windows/serviceinstall`](../internal/platform/windows/serviceinstall) implements create-new registration for only that fixed service. It derives the protected command from the installation root, creates the LocalSystem service disabled, applies an exact LocalSystem/Administrators-only service DACL first, sets bounded restart/no-command recovery, enables automatic start last, and independently queries every setting. Its SCM manager handle has only connect/create rights; pre-existing detection has query-only rights and never adopts the object. The rollback lease can delete only the service positively created by its own native create call. [ADR 0016](adr/0016-windows-broker-service-registration.md) records the policy and evidence limits. Service start, persistent attempt state, and hosted upload remain unimplemented.

[`internal/platform/windows/installer`](../internal/platform/windows/installer) composes the create-new Windows ownership graph. It pins the validated specification plus trusted PE/source-bound broker bytes before mutation, then orders accounts/SID binding, filesystem convergence, a fixed protected root/image/state, immediate execution-password clearing, and service registration. One uncommitted lease rolls those components back in reverse order and exposes the remaining control credential only as a cleared temporary copy to the later runner-service installer. [ADR 0017](adr/0017-windows-create-new-installer-transaction.md) records why the CLI cannot commit this lease before runner setup. Installer CLI/runner integration, service start, persistent attempt state, and hosted upload remain unimplemented.

The workstation produces a strict non-authoritative `ExecutionReport`. It cannot contain hosted `finalized_at` or workflow provenance. [`protocol/v1`](../protocol/v1) can form an authoritative `ResultRecord` only when a finalizer supplies a valid accepted record, a bound report, canonical finalization time, and matching hosted workflow provenance.

## Windows restricted process boundary

[`internal/platform/windows/process`](../internal/platform/windows/process) implements the native launcher required by the shared lifecycle. It has no `os/exec` or current-user fallback. A broker token source must supply a lease for the configured execution identity, and the launcher independently requires both token user and primary-group SIDs to match the authorized principal.

The file-backed token source is fixed to one local execution account and protected absolute credential path. The shared protected-state reader opens with no sharing, rejects non-disk, reparse, empty, oversized, or multiply linked files, binds the canonical final path to the configured path, requires the exact SYSTEM/Administrators-only protected DACL, and revalidates stable handle metadata after reading. The token source then uses machine-scoped/no-UI DPAPI, batch-only `LogonUserW`, and `LoadUserProfileW`. Plaintext byte and UTF-16 buffers are bounded and cleared after use; the lease unloads the profile before closing the token. Machine-scoped DPAPI is not an identity boundary, so a bad credential-file ACL is a closed failure. [ADR 0007](adr/0007-windows-protected-batch-token-source.md) records this decision and its evidence limits.

The launcher re-resolves the approved working directory near launch, builds a Unicode environment from only sanitized entries, and limits inherited handles to the child ends of stdin/stdout/stderr using an extended startup handle list. It calls `CreateProcessAsUserW` suspended, assigns the process to a kill-on-close Job Object, then resumes it. Script bytes flow only through stdin. Normal completion, timeout, and cancellation all reap the full Job Object before the shared lifecycle receives a terminal signal. [ADR 0006](adr/0006-windows-restricted-process-and-job-boundary.md) records the detailed decision.

Local Windows tests exercised actual Job Object termination of a test process and its descendant, real DPAPI round-trip/tamper rejection, ACL policy parsing and ordinary-file denial, a real failed batch logon for a synthetic nonexistent account, and a read-only fixed-service query. These prove native mechanisms, not the installed identity boundary. Account/service registration mechanisms are implemented but successful elevated provisioning, LocalSystem-to-execution-account logon/profile/process launch, installed service lifecycle, and dedicated-account/service ACL denial still require isolated E2E evidence.

## Native enforcement still required

The following mechanisms are not implemented by this checkpoint and remain release blockers:

| Boundary | Windows requirement | Linux requirement |
|---|---|---|
| Broker service | lifecycle and create-new registration implemented; installed LocalSystem start/stop/recovery/ACL E2E remains | root-owned hardened systemd service |
| Peer authentication | mechanism implemented: exact named-pipe DACL, first-instance/remote-client rejection, impersonated caller SID verification, mandatory revert; installed-account/remote-host E2E remains | filesystem socket owner/group/mode plus `SO_PEERCRED` UID verification |
| Identity transition | installer-created account/logon right and installed LocalSystem E2E (the protected batch token source/profile lease and token-validating launcher are implemented) | fixed nonzero UID/GID/supplementary groups, cleared capabilities, no-new-privileges before `execve` |
| Filesystem | account/root ACL grants plus elevated installed-host verification (protected broker-state descriptors/store and near-launch authorization checks are implemented) | native symlink/final-path checks reinforced by ownership/ACL denial |
| Process lifecycle | installed-token E2E remains (Job Object ownership/termination is implemented and native-tested) | process group/session with TERM grace then KILL |
| Result data | native stdout/stderr plumbing, execution-authority artifact bundle, bounded local response stream, and atomic control destination implemented; installed integration/hosted upload remain | native stdout/stderr plumbing and bounded artifacts accessed under execution authority |

Hosted Windows/Linux unit tests demonstrate parser, configuration, environment, bounded-capture, and shared fail-closed lifecycle behavior. Fake launchers, processes, timers, resolvers, and collectors are orchestration evidence only. They cannot demonstrate the native rows above; those claims require isolated real-host tests under the actual dedicated identities.

## Security consequences

The implemented shared layer narrows what a future broker may accept and makes unsafe authority fields structurally unavailable. It is defense against confused-deputy behavior, not a substitute for OS isolation.

Until the remaining native boundaries, installed negative credential/filesystem/service tests, and full isolated-host integration are implemented and inspected, AWG must not be described as installable, runtime-verified, or safe for workstation execution.
