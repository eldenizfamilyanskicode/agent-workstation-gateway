# ADR 0021 — Linux systemd, UID, and Unix-Socket Boundary

- Status: Accepted
- Date: 2026-09-03
- Scope: Linux service, local IPC, identity transition, filesystem authority, and process lifetime

## Context

The private GitHub runner must retain only control-plane authority. Arbitrary scripts must run as a different local identity and must not acquire runner credentials, GitHub credentials, broker configuration, or root authority.

## Decision

AWG v0.1 uses two fixed systemd services and two dedicated system users:

- `agent-workstation-gateway-runner.service` runs the official GitHub runner as the control user;
- `agent-workstation-gateway-broker.service` runs the narrow broker as root;
- the broker listens only on `/run/agent-workstation-gateway/broker.sock`;
- the socket and its directory are owned by root and the control group, while `SO_PEERCRED` must report the exact configured control UID;
- each workload is created in a new process group under the fixed execution UID/GID, with an empty supplementary-group list and empty capability sets;
- the child verifies its identity, clears dumpability, and applies `PR_SET_NO_NEW_PRIVS` before `execve`;
- timeout, explicit stop, and broker shutdown signal the complete process group with TERM followed by KILL and reap descendants;
- artifact enumeration and file opening happen in a separate helper under the execution identity, never through root read authority.

The installer creates both users and groups, stores the runner outside the protected broker root, grants the execution user ACL access only to explicit approved roots, and records the original ACLs for uninstall. The broker systemd unit has a strict filesystem view and a capability bounding set limited to identity transition, ownership adjustment, and process termination. The same exact set is ambient only so it survives the unit's `NoNewPrivileges` exec boundary; the post-transition helper explicitly clears every inheritable, permitted, effective, and ambient capability before executing workload code. Both units disable `RestrictSUIDSGID`: the broker must use `setresuid`/`setresgid` for its fixed transition to the execution identity, while current WSL kernels return `ENOSYS` for GNU tar's safe `openat2` calls under that filter and prevent the runner from materializing immutable GitHub actions. The protected installation root permits execute-only traversal so the helper can re-execute the root-owned broker image; the `state` directory remains root-only `0700`. The runner still cannot read protected installation state, and its root remains writable only by the non-root control identity.

Linux control responses are written create-new into a control-owned staging directory and atomically renamed. Any symlink in the destination chain is rejected.

## Rejected alternatives

- Running workloads as the GitHub runner user collapses credentials and arbitrary code into one authority.
- A broad sudoers rule makes the control runner a generic privilege boundary.
- Reading artifacts as root allows a request to turn path selection into privileged file disclosure.
- Shell detachment is not a supported persistence mechanism; background work remains broker-owned and bounded.

## Consequences

The root broker remains security-sensitive, but its normal interface cannot select a user, executable, credential, or filesystem root outside protected installation policy. Linux requires systemd, procfs, Unix peer credentials, POSIX ACL tools, and dedicated local identities.

Container tests exercise the native UID/GID, capability, socket, symlink, artifact, and process-group mechanisms. Those results do not substitute for the required installed WSL2/systemd lifecycle test.
