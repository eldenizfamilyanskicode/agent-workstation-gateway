# Windows Implementation and Installation State

Windows x64 is AWG's first native implementation target. The repository is still pre-alpha: native path, token, process, Job Object, protected-state, and planning mechanisms exist, but account provisioning, rights, service/IPC installation, and installed-host E2E are not complete.

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

## Evidence limits

Hosted and local Windows tests cover strict planning, no-mutation dry-run behavior, materializer ordering/zeroing, exact ACL descriptor policy, ordinary-parent denial before artifact creation, DPAPI mechanism behavior, and compatibility with the token source's ACL validator.

They do not prove successful elevated convergence to a LocalSystem owner, account creation, effective logon-right assignment, LocalSystem service behavior, or execution-account denial. The native account package performs only a real absent-name query during ordinary tests; all mutating account/LSA evidence is a later isolated-smoke gate. Cross-compilation is not Windows security evidence.
