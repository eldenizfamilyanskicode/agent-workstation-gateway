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

The envelope contract does not authenticate a caller. The native Windows named pipe or Linux Unix socket must authenticate the peer before accepting the envelope.

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

Artifact collection is a separate injected native boundary. Its plan contains only the fixed execution identity, resolved working directory, and accepted selections—not the script, shell arguments, or environment. Collector failure becomes explicit `collection_failed` omissions without overwriting the command outcome. Native enumeration, link/reparse rejection, byte transport, and reads under the execution identity remain unimplemented.

The workstation produces a strict non-authoritative `ExecutionReport`. It cannot contain hosted `finalized_at` or workflow provenance. [`protocol/v1`](../protocol/v1) can form an authoritative `ResultRecord` only when a finalizer supplies a valid accepted record, a bound report, canonical finalization time, and matching hosted workflow provenance.

## Native enforcement still required

The following mechanisms are not implemented by this checkpoint and remain release blockers:

| Boundary | Windows requirement | Linux requirement |
|---|---|---|
| Broker service | LocalSystem Windows service | root-owned hardened systemd service |
| Peer authentication | explicit named-pipe DACL, remote-client rejection, impersonated caller SID verification, mandatory revert | filesystem socket owner/group/mode plus `SO_PEERCRED` UID verification |
| Identity transition | broker-only protected batch-logon secret, `LogonUserW`, profile/token lifecycle, `CreateProcessAsUserW` | fixed nonzero UID/GID/supplementary groups, cleared capabilities, no-new-privileges before `execve` |
| Filesystem | near-launch final-path recheck and ACL denial (the authorization resolver is implemented) | native symlink/final-path checks reinforced by ownership/ACL denial |
| Process lifecycle | Job Object tree ownership and termination | process group/session with TERM grace then KILL |
| Result data | native stdout/stderr plumbing and bounded artifacts accessed under execution authority | native stdout/stderr plumbing and bounded artifacts accessed under execution authority |

Hosted Windows/Linux unit tests demonstrate parser, configuration, environment, bounded-capture, and shared fail-closed lifecycle behavior. Fake launchers, processes, timers, resolvers, and collectors are orchestration evidence only. They cannot demonstrate the native rows above; those claims require isolated real-host tests under the actual dedicated identities.

## Security consequences

The implemented shared layer narrows what a future broker may accept and makes unsafe authority fields structurally unavailable. It is defense against confused-deputy behavior, not a substitute for OS isolation.

Until native peer authentication, protected configuration storage, identity transition, path resolution, process control, negative credential/filesystem tests, and service lifecycle are implemented and inspected, AWG must not be described as installable, runtime-verified, or safe for workstation execution.
