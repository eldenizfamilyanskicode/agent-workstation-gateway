# Secure Execution Architecture

This document describes the implemented shared execution-policy core and the native Windows/Linux mechanisms still required before Agent Workstation Gateway can execute a request securely. The repository remains pre-alpha and does not yet contain a usable broker service.

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

The shared policy independently checks that returned paths are canonical, that the root is configured, and that the directory is segment-contained. A mock resolver proves only shared orchestration behavior. It is not Windows or Linux filesystem-boundary evidence.

## Native enforcement still required

The following mechanisms are not implemented by this checkpoint and remain release blockers:

| Boundary | Windows requirement | Linux requirement |
|---|---|---|
| Broker service | LocalSystem Windows service | root-owned hardened systemd service |
| Peer authentication | explicit named-pipe DACL, remote-client rejection, impersonated caller SID verification, mandatory revert | filesystem socket owner/group/mode plus `SO_PEERCRED` UID verification |
| Identity transition | broker-only protected batch-logon secret, `LogonUserW`, profile/token lifecycle, `CreateProcessAsUserW` | fixed nonzero UID/GID/supplementary groups, cleared capabilities, no-new-privileges before `execve` |
| Filesystem | native final-path/reparse checks reinforced by ACL denial | native symlink/final-path checks reinforced by ownership/ACL denial |
| Process lifecycle | Job Object tree ownership and termination | process group/session with TERM grace then KILL |
| Result data | bounded output/artifacts accessed under execution authority | bounded output/artifacts accessed under execution authority |

Hosted Windows/Linux unit tests demonstrate parser, configuration, environment, and shared fail-closed policy behavior. They cannot demonstrate the native rows above. Those claims require isolated real-host tests under the actual dedicated identities.

## Security consequences

The implemented shared layer narrows what a future broker may accept and makes unsafe authority fields structurally unavailable. It is defense against confused-deputy behavior, not a substitute for OS isolation.

Until native peer authentication, protected configuration storage, identity transition, path resolution, process control, negative credential/filesystem tests, and service lifecycle are implemented and inspected, AWG must not be described as installable, runtime-verified, or safe for workstation execution.
