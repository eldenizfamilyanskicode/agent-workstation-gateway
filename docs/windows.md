# Windows Implementation and Installation State

Windows x64 is AWG's first native implementation target. The repository is still pre-alpha: native path, token, process, Job Object, protected-state, account, rights, workload-ACL, and authenticated named-pipe mechanisms exist, but mutating installation, service installation, broker integration, and installed-host E2E are not complete.

## Installation input versus installed configuration

The user-facing Windows install specification is intentionally different from the broker's installed configuration.

The strict input contract at [`config/schemas/v1/windows-install.schema.json`](../config/schemas/v1/windows-install.schema.json) accepts:

- one administrator-selected canonical installation root;
- distinct local control/execution account names;
- approved development roots;
- fixed shell executable bindings;
- dedicated execution profile/temp paths;
- allowlisted PATH entries and explicit optional capabilities.

It cannot contain account SIDs, an execution credential or credential-file path, a service command, a pipe ACL, or another privileged operation. A later account-provisioning layer resolves the actual SIDs and binds them into the strict installed configuration.

The synthetic example is [`config/examples/v1/windows-install.json`](../config/examples/v1/windows-install.json).

## Mutation-free dry-run

The initial management CLI exposes only planning:

```powershell
go run ./cmd/awg install --dry-run --spec config/examples/v1/windows-install.json
```

The command strictly decodes the bounded specification and writes one deterministic JSON plan to stdout. It performs no account, filesystem, ACL, credential, service, runner, repository, or network mutation. It never generates a password or DPAPI blob.

Non-dry-run installation is deliberately rejected until the account/rights/service transaction is implemented and verified.

## Account and logon-right transaction

The create-new account transaction is implemented behind an elevated native boundary but is not yet enabled by the CLI. Both configured names must be absent before password generation. It generates independent mutable credentials, creates only normal local users, resolves their real SIDs, and binds those SIDs into installed configuration.

Both accounts must have built-in Users as their only reported local group. Control receives service logon plus interactive/RDP deny rights. Execution receives batch logon plus interactive/RDP/service deny rights. The right strings and memberships are product policy, not installer input. [ADR 0008](adr/0008-windows-local-account-and-logon-right-provisioning.md) records the exact sets and create-new decision.

The transaction tracks NetAPI's created/not-created result even when a post-create step fails. Closing an uncommitted lease deletes only accounts positively created by that lease, in reverse order, and clears both credentials. Commit preserves accounts and clears credentials. Pre-existing names are never adopted or deleted.

## Workload filesystem boundary

The deterministic dry-run plan includes one `grant_execution_modify` operation for each approved root followed by fixed profile/temp operations. These operations are administrator-local installation policy; they are not accepted by the execute-only broker endpoint.

The native backend is constructed from the validated SID-bound installed configuration and refuses other paths or SIDs. Approved roots must already exist. It opens each root without sharing or reparse traversal, compares the same-handle final path, preserves its owner/DACL protection and other principals, and replaces only direct execution-SID entries with one inheritable Modify ACE. It rejects unsupported ACE forms, conflicting inherited execution ACEs, execution ownership, and relevant broad-principal rights that would either deny the required access or grant ACL management.

Profile/temp leaves require an existing canonical parent. Missing leaves are created with a bounded installer bootstrap ACE long enough to acquire the verified handle, then converged to a protected three-principal DACL: LocalSystem and Administrators receive Windows file Full Access; execution receives Modify without `WRITE_DAC` or `WRITE_OWNER`. Existing leaves are converged through the same handle.

The filesystem lease retains original descriptors only until commit/rollback. Rollback restores existing DACLs and their inheritance-protection state in reverse order, and removes only an empty leaf positively created by the active transaction. It does not recursively rewrite approved-root children. [ADR 0009](adr/0009-windows-workload-filesystem-acls.md) records the exact policy and residual evidence requirements.

## Fixed protected layout

For an installation root such as `C:\ProgramData\AgentWorkstationGateway`, the product derives rather than accepts these paths:

```text
C:\ProgramData\AgentWorkstationGateway\bin
C:\ProgramData\AgentWorkstationGateway\state
C:\ProgramData\AgentWorkstationGateway\state\execution-credential.dpapi
C:\ProgramData\AgentWorkstationGateway\state\installation.json
```

The installation root may not be a drive root and may not overlap any approved workload, profile, or temporary root. Product-owned state paths never come from a remote request.

The native store converges gateway-owned directories to a protected LocalSystem/Administrators-only DACL. Protected files have explicit non-inherited LocalSystem/Administrators-only full-control ACEs. It opens directories/files with `FILE_FLAG_OPEN_REPARSE_POINT`, compares same-handle final paths, and rejects aliases or reparse points.

File updates use a cryptographically random sibling temporary name, exclusive native creation with the final protected descriptor, bounded writes, `FlushFileBuffers`, close, and write-through replacement. The resulting handle path, type, size, owner, and DACL are checked again. Temporary files are removed on failed writes.

Materialization writes the DPAPI credential first and canonical SID-bound installed configuration last. The configuration is the completion marker for this bounded state layer; future repair/update must stop the broker before rotating both files.

## Credential handling

The materializer accepts a caller-owned bounded UTF-8 password, copies it, clears its own copy, seals through the Windows DPAPI implementation, and clears its protected-blob working copy after the store returns. The caller that generated the password remains responsible for clearing its original buffer.

No plaintext password is written to the plan, configuration, filesystem, environment, command line, output, error, or test fixture. See [ADR 0007](adr/0007-windows-protected-batch-token-source.md) for the DPAPI/ACL/token decision.

## Authenticated broker pipe

The Windows transport uses the fixed local name `\\.\pipe\agent-workstation-gateway-v1`; requests cannot select an endpoint, descriptor, SID, mode, or buffer size. It creates one overlapped message-mode instance with first-instance anti-squatting and remote-client rejection flags, then queries the created handle to require an exact protected DACL.

LocalSystem and Administrators receive Full Access. The installed control SID receives the individual duplex pipe rights required by Windows, but not `FILE_APPEND_DATA`/`FILE_CREATE_PIPE_INSTANCE`, DACL/owner management, or system-security access. No execution, Everyone, or anonymous ACE is present.

The client sends a fixed four-byte preface so the server can read a message before calling `ImpersonateNamedPipeClient`. The server pins the OS thread, compares the impersonated thread token's exact TokenUser SID with installed control identity, and always reverts before exposing the connection to the bounded record decoder. An administrator SID does not bypass that comparison. Reversion failure terminates the process. Application records use a four-byte big-endian length with a 256 KiB ceiling. See [ADR 0010](adr/0010-windows-authenticated-named-pipe.md).

## Bounded artifact collection

Post-command artifact selection is implemented as execution-authority filesystem access, not a LocalSystem file proxy. The collector validates the token's exact execution user/primary group, pins and impersonates that token, then opens the configured root, working directory, and matched files before reverting. Root/working handles require exact final paths; candidates must be regular single-link disk files with no reparse attribute and a final path still beneath both guards.

Portable case-sensitive slash globs support recursive `**`. Enumeration skips sensitive segments and is capped at 8,192 entries and 32 segments deep. Protocol limits cap the result at 256 files, 512 MiB per file, and 1 GiB total. Size is checked before hashing. Each file remains held by the same one-shot handle used for SHA-256, with write/delete sharing denied until the reader or bundle closes. The later broker response must stream these handles and the control side must verify the digest before GitHub upload. See [ADR 0011](adr/0011-windows-execution-authority-artifacts.md).

## Evidence limits

Hosted and local Windows tests cover strict planning, no-mutation dry-run behavior, materializer ordering/zeroing, protected-state descriptor policy, ordinary-parent denial before artifact creation, DPAPI mechanism behavior, compatibility with the token source's ACL validator, real temporary-directory workload-ACL convergence/rollback, real local named-pipe descriptor/authentication/framing behavior, and current-token artifact collection/handle stability/hard-link/quota behavior.

They do not prove successful elevated convergence to a LocalSystem owner, account creation, effective logon-right assignment, LocalSystem service behavior, or effective installed execution-account access/denial. The pipe test treats the current process as the synthetic control SID; it does not prove installed control success, installed execution/unrelated-user denial, non-control administrator rejection, or remote-host rejection. Artifact tests likewise use the current token and do not prove allowed/denied reads by installed execution identity; the local reparse test can skip without symbolic-link privilege. The workload-ACL tests use a nonexistent synthetic SID under fresh temporary directories and restore/remove their own state. The native account package performs only a real absent-name query during ordinary tests; all mutating account/LSA and installed-token evidence is a later isolated-smoke gate. Cross-compilation is not Windows security evidence.
