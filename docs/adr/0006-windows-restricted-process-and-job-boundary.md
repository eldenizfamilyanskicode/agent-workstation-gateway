# ADR 0006 — Windows Restricted Process and Job Boundary

- Status: Accepted
- Date: 2026-09-03
- Scope: Windows token validation, process creation, inherited handles, and process-tree ownership

## Context

The shared lifecycle cannot safely use `os/exec`: the broker runs with more authority than arbitrary workload and must make a fixed transition to the configured execution identity. Windows process creation also does not automatically own descendants for timeout, cancellation, or ordinary job completion.

The boundary must prevent three common failure modes:

- retrying a failed restricted launch under the broker or control identity;
- leaking unrelated inheritable broker handles into a workload;
- killing only the root process while descendants continue with workstation access.

## Decision

The Windows launcher in [`internal/platform/windows/process`](../../internal/platform/windows/process) has no current-user or generic process-launch fallback. It requires a broker-provided `TokenSource` for the one configured execution principal.

Before process creation, the launcher:

1. repeats handle-based working-directory resolution against the resolver-selected approved root;
2. acquires a primary token lease for the fixed execution principal;
3. queries the token user and primary-group SIDs and requires both to match protected configuration;
4. constructs the command line only from the configured executable and closed shell arguments;
5. constructs a sorted Unicode environment block only from the shared sanitized environment;
6. creates anonymous stdin/stdout/stderr pipes and clears inheritance on every parent end;
7. supplies an explicit `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` containing only the three child pipe ends.

The launcher calls `CreateProcessAsUserW` with the exact application path, suspended creation, the Unicode environment, explicit working directory, and extended startup information. It creates a private Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, assigns the suspended process to that Job Object, and only then resumes its primary thread.

Requester script bytes are written to the child stdin pipe. They are never part of the application path or command line. Stdout and stderr are drained concurrently so pipe capacity cannot deadlock a running child.

The process owner treats the entire Job Object as one attempt:

- timeout/cancellation calls `TerminateJobObject` and waits for the owned process count to reach zero;
- after an ordinary root exit, remaining descendants are also terminated because v0.1 requests do not grant persistence;
- stdout/stderr drains finish before terminal exit is reported;
- process, thread, pipe, Job Object, and token-lease handles are closed on success and failure paths;
- a failure to create, assign, resume, terminate, drain, query, or reap becomes a runtime failure, never a retry under another token.

## Token lease boundary

`TokenSource` and `TokenLease` are deliberately narrow. The file-backed Windows source now owns protected credential retrieval, batch-only `LogonUserW`, profile loading, and lease cleanup as recorded in [ADR 0007](0007-windows-protected-batch-token-source.md). Request fields cannot select a username, SID, credential, logon type, or token.

The lease remains live until the whole process tree is reaped, then unloads profile state before closing the token. The launcher independently checks token SIDs even when the source claims it returned the right identity.

## Alternatives considered

### `os/exec.Cmd`

Rejected for production privileged launch. It does not express the required fixed token transition and would make an accidental broker-identity fallback too easy.

### `CreateProcessW` fallback

Rejected. A restricted-token failure is a terminal runtime failure, not permission to run as LocalSystem or the control identity.

### Launch first, assign Job Object afterward

Rejected. An unsuspended process can create a descendant before assignment. Suspended creation closes that gap for the initial process.

### Inherit all inheritable broker handles

Rejected. Even if AWG attempts to keep its own handles non-inheritable, unrelated service/library state must not silently cross the boundary. The explicit handle list is defense in depth.

### Kill only the root PID

Rejected. Descendants may retain files, credentials, network access, or mutation authority after timeout. The Job Object is the lifecycle unit.

## Consequences and evidence limits

Native Windows tests exercise SID comparison, command/environment construction, inherited-handle policy construction, and real Job Object termination of a root process plus descendant. Hosted Windows tests compile and run those mechanisms.

Separate token-source tests exercise real machine-scoped DPAPI round-trip/tamper rejection, protected-DACL policy, and negative batch logon. They do not yet prove that an installed LocalSystem service can log on the dedicated execution account, load its profile, or launch with its token. They also do not prove installer-created ACL denial of control credentials. That evidence requires installer-created accounts/ACLs and isolated real-host E2E.

The base implementation remains cgo-free and uses the `golang.org/x/sys/windows` dependency accepted by ADR 0005.

## Verification requirements

- mismatch tests for token user and primary-group SIDs with non-echoing errors;
- tests proving script bytes are absent from the trusted command line;
- malformed/duplicate environment rejection;
- real Windows Job Object descendant termination;
- failure-path handle/token cleanup tests where injectable seams permit them;
- installed-service E2E under distinct control and execution identities before a usable-release claim;
- negative tests proving workload denial for runner credentials, broker state, and unrelated user data.

## References

- Microsoft — `CreateProcessAsUserW`: https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw
- Microsoft — Job Objects: https://learn.microsoft.com/windows/win32/procthread/job-objects
- Microsoft — `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`: https://learn.microsoft.com/windows/win32/procthread/attribute-list
- Microsoft — `TerminateJobObject`: https://learn.microsoft.com/windows/win32/api/jobapi2/nf-jobapi2-terminatejobobject
