# ADR 0007 — Windows Protected Batch Token Source

- Status: Accepted
- Date: 2026-09-03
- Scope: Windows execution-account credential protection, credential-file access, batch logon, and profile lifetime
- Supersedes: the Windows DPAPI scope choice in ADR 0001

## Context

The restricted Windows launcher requires a primary token for one installed local execution account. A request must not select an account, submit a credential, change the logon type, or cause fallback to the broker identity.

The launch password is an implementation mechanism, not workload authority. Its plaintext must be short-lived and absent from disk, environment, command line, logs, errors, and results. The protected blob must also be unreadable by the execution identity: machine-scoped DPAPI protects data at rest but does not by itself distinguish users on the same machine.

ADR 0001 selected LocalSystem user-scope DPAPI. The implementation instead needs an elevated installer to provision an offline protected blob that a later LocalSystem service can consume. This ADR changes that scope choice while adding a mandatory file-ACL enforcement boundary.

## Decision

[`internal/platform/windows/process`](../../internal/platform/windows/process) implements a file-backed `TokenSource` fixed at construction to:

- one validated local account name in the local `.` domain;
- its configured user and primary-group SIDs;
- one canonical absolute credential-file path.

An acquire request must match all three configured principal fields before credential storage is touched. The source has no interactive, network, current-token, or alternate-account path.

### Credential protection

`ProtectPassword` accepts only non-empty, valid UTF-8 without NUL bytes and limits plaintext to 1,024 bytes. It calls `CryptProtectData` with:

- `CRYPTPROTECT_LOCAL_MACHINE`;
- `CRYPTPROTECT_UI_FORBIDDEN`;
- fixed application entropy versioned for the Windows execution credential.

Unprotection also forbids UI. Protected input is limited to 65,536 bytes, decrypted plaintext is revalidated against the plaintext limit, and DPAPI integrity failure is closed to a non-echoing rule. Controllable Go and native plaintext buffers are cleared; native DPAPI allocations are cleared before `LocalFree`.

Machine scope is not treated as authorization. A local principal that obtains the blob may be able to ask DPAPI to decrypt it. The protected file boundary below is therefore mandatory rather than optional hardening.

### Protected credential file

The source opens exactly the configured file with `CreateFileW`, no sharing, and `FILE_FLAG_OPEN_REPARSE_POINT`. It uses that same handle to:

1. reject a directory, reparse point, empty file, or oversized file;
2. obtain and compare the normalized final DOS path with the configured path;
3. query owner and DACL security information;
4. read the bounded ciphertext;
5. re-query identity and size after the read.

The file owner must be LocalSystem or built-in Administrators. Its DACL must be present and protected from inheritance. Allow ACEs may name only LocalSystem or built-in Administrators, and both must have read access. Inherited or unknown allow-capable ACE types are rejected. Deny ACEs do not widen authority.

This check does not replace installer ACL creation. It makes an unexpected ACL, alias, or replacement a startup/acquisition failure instead of silently trusting it.

### Token and profile lifetime

After a protected read, the source decrypts into bounded memory, converts UTF-8 directly into a mutable UTF-16 buffer, and calls `LogonUserW` with exactly `LOGON32_LOGON_BATCH` and the default provider. It clears plaintext byte and UTF-16 buffers immediately after their native use.

Successful logon is followed by `LoadUserProfileW` with `PI_NOUI`. A `TokenLease` owns both the profile handle and primary token. Closing the lease unloads the profile before closing the token, exactly once. If profile loading fails, the token is closed. If context cancellation is observed after profile loading, the complete lease is closed before returning.

The process launcher still independently checks the token user and primary-group SIDs against protected configuration before calling `CreateProcessAsUserW`. Account deletion/recreation under the same name therefore cannot bypass the configured SID binding.

## Alternatives considered

### LocalSystem user-scope DPAPI

This was ADR 0001's original choice. It gives DPAPI identity binding in addition to file ACLs, but requires the LocalSystem service itself to perform initial protection or another privileged IPC/provisioning step. For v0.1, machine scope plus a strict, runtime-validated SYSTEM/Administrators-only file boundary is simpler and keeps installation offline. Copying the ciphertext outside that boundary is consequently more dangerous and must be treated as a credential disclosure.

### Windows Credential Manager or LSA private data

Deferred. They add different lifecycle, service, recovery, and dependency surfaces without eliminating the need for a narrow fixed-account token source. A later change requires a new ADR and migration design.

### Interactive logon or current-token fallback

Rejected. It would collapse identity separation whenever the dedicated account or its logon right is broken. Batch-logon failure is terminal.

### Request-supplied account or credential

Rejected. The broker is an execute-only mediator, not a general credential or run-as service.

## Consequences and evidence limits

Native Windows tests perform a real machine-scoped DPAPI round trip, reject a tampered blob, exercise bounded/zeroable password conversion, parse accepted and rejected ACL descriptors, reject an ordinary user-owned file, and perform a real negative batch-logon attempt without echoing account or password data.

These mechanism tests do not prove successful LocalSystem decryption, the installer-created file ACL, `SeBatchLogonRight`, profile load/unload for the dedicated account, or `CreateProcessAsUserW` under that account. Those require elevated installer work and isolated installed-service E2E. No real credential blob is a repository fixture.

## Verification requirements

- real Windows DPAPI round-trip and tamper rejection;
- bounded plaintext/blob and non-echoing negative tests;
- ACL descriptor allow/deny tests and ordinary-file rejection;
- negative batch logon with no fallback;
- installer tests for exact file owner/protected DACL and execution-account denial;
- installed LocalSystem-to-dedicated-account logon/profile/process E2E;
- negative workload reads of the blob, broker state, runner credentials, and unrelated user data.

## References

- Microsoft — `CryptProtectData`: https://learn.microsoft.com/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata
- Microsoft — `CryptUnprotectData`: https://learn.microsoft.com/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata
- Microsoft — `LogonUserW`: https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-logonuserw
- Microsoft — `LoadUserProfileW`: https://learn.microsoft.com/windows/win32/api/userenv/nf-userenv-loaduserprofilew
- Microsoft — `GetSecurityInfo`: https://learn.microsoft.com/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo
