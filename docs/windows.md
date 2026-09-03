# Windows Implementation and Installation State

Windows x64 is AWG's first native implementation target. The repository is still pre-alpha: native path, token, process, Job Object, protected-state, account, rights, workload-ACL, authenticated named-pipe, broker startup-composition, SCM lifecycle, service registration, and create-new installer-transaction mechanisms exist, but installer CLI/runner composition, control-side integration, and installed-host E2E are not complete.

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

The transaction tracks NetAPI's created/not-created result even when a post-create step fails. Closing an uncommitted lease deletes only accounts positively created by that lease, in reverse order, and clears both credentials. The composite installer clears the execution credential immediately after protected-state materialization; final commit preserves accounts and clears the remaining control credential. Pre-existing names are never adopted or deleted.

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

The client sends a fixed four-byte preface so the server can read a message before calling `ImpersonateNamedPipeClient`. The server pins the OS thread, compares the impersonated thread token's exact TokenUser SID with installed control identity, and always reverts before exposing the connection to the bounded record decoder. An administrator SID does not bypass that comparison. Reversion failure terminates the process. Application records use a four-byte big-endian length with a 256 KiB ceiling. Context-aware overlapped reads/writes allow the broker session to cancel stalled operations. See [ADR 0010](adr/0010-windows-authenticated-named-pipe.md).

One authenticated connection now maps to one broker session: bounded envelope read, strict decode, authorization, shared execution lifecycle, report binding, and one terminal response. Default fixed local deadlines are 30 seconds for the request, 30 minutes for response streaming, and 30 seconds per terminal-ack read. A request cannot change them. The completion ACK prevents premature message-pipe disconnect; invalid or absent ACK remains bounded and fails the exchange.

The Windows broker host now loads only exact protected state paths derived from the installation root, denies overlap with every execution-owned root, obtains the Windows directory through the native API instead of copying the service environment, and composes the real token/launcher/collector/session/listener graph without a current-user fallback. Credential protection is revalidated on every acquisition. Each accepted connection is closed after one session. See [ADR 0014](adr/0014-windows-broker-startup-composition.md).

## SCM broker lifecycle

`awg-broker.exe` is now a service-only binary with the fixed SCM name `AgentWorkstationGatewayBroker`. Its image command line accepts only the administrator-protected installation root. The exact public source commit is embedded by trusted release builds; an empty, uppercase, symbolic, or otherwise non-lowercase-40-hex source value fails startup. There is no interactive console fallback.

Before protected-state loading, the service requires an actual SCM process context and exact LocalSystem TokenUser. It reports bounded StartPending/Running/StopPending states and accepts only Stop/Shutdown. Shutdown cancels execution, closes the listener and any active connection to interrupt IPC, and waits for the owned sequential loop. Only closed peer/session failures continue to another accept; listener infrastructure and handle-close failures terminate the service. See [ADR 0015](adr/0015-windows-scm-broker-service.md).

The binary can be built for inspection with a synthetic source value:

```powershell
go build -ldflags "-X main.gatewaySourceSHA=0123456789abcdef0123456789abcdef01234567" ./cmd/awg-broker
```

This does not install or start the service.

The native service-registration boundary now accepts only the canonical installation root. It derives the fixed protected broker path and exact argument, requests only SCM connect/create rights, and checks a possible pre-existing fixed service with query-only access. A collision fails closed without adoption or deletion.

Creation is staged disabled. The exact protected LocalSystem-owner/group DACL grants full service access only to LocalSystem and Builtin Administrators and is applied before recovery configuration. Recovery permits restarts after 5 and 30 seconds followed by no action, has no command or reboot behavior, and resets after 24 hours. Automatic start is applied last, then configuration, recovery, and descriptor state are queried independently. An uncommitted lease deletes only a service positively created by that lease. See [ADR 0016](adr/0016-windows-broker-service-registration.md).

This boundary is not yet wired into a complete installer and does not start the service. Repair, update, and uninstall orchestration remain separate work.

## Create-new installer transaction

The Windows composite installer now pins a strict specification, canonical source SHA, and trusted bounded PE32+ AMD64 broker image before mutation. The image must contain the build-embedded exact SHA and cannot be a DLL. This does not authenticate downloaded bytes: release/bootstrap code must still verify published artifact provenance before invoking the transaction.

The fixed sequence performs a read-only service collision query, creates accounts and binds their SIDs, converges workload filesystem leases, creates a new protected root/image/state, clears the execution password after DPAPI materialization, and finally registers the verified service. No spec/request field chooses the broker destination, protected state paths, service policy, account rights, or stage order.

One uncommitted lease owns reverse cleanup: service, exact known protected files and empty directories, filesystem changes, then accounts. It refuses to adopt an existing installation root and never recursively deletes unknown content. A temporary copy provides the control password only to a later synchronous trusted runner-service consumer and is cleared on return. The account-owned original remains until the larger setup commits or rolls back. See [ADR 0017](adr/0017-windows-create-new-installer-transaction.md).

The transaction is not exposed by `awg install` yet. It does not install a runner, select a private repository, start the broker, implement repair/update/uninstall, or constitute elevated-host evidence.

## Bounded artifact collection

Post-command artifact selection is implemented as execution-authority filesystem access, not a LocalSystem file proxy. The collector validates the token's exact execution user/primary group, pins and impersonates that token, then opens the configured root, working directory, and matched files before reverting. Root/working handles require exact final paths; candidates must be regular single-link disk files with no reparse attribute and a final path still beneath both guards.

Portable case-sensitive slash globs support recursive `**`. Enumeration skips sensitive segments and is capped at 8,192 entries and 32 segments deep. Protocol limits cap the result at 256 files, 512 MiB per file, and 1 GiB total. Size is checked before hashing. Each file remains held by the same one-shot handle used for SHA-256, with write/delete sharing denied until the reader or bundle closes.

The platform-neutral response layer now streams those exact handles in manifest order through 64 KiB frames and requires exact size/SHA-256 at both ends. Retained stdout/stderr receive separate prefix hashes because report hashes cover complete streams even when their returned prefixes are truncated. A control-side artifact transaction commits only after all content, the completion handshake, and terminal EOF validate; otherwise it aborts. The broker session is wired to this response layer, but the control filesystem sink and GitHub upload are not yet implemented. See [ADR 0011](adr/0011-windows-execution-authority-artifacts.md) and [ADR 0012](adr/0012-bounded-local-broker-response-stream.md).

## Evidence limits

Hosted and local Windows tests cover strict planning, no-mutation dry-run behavior, materializer ordering/zeroing, exact protected-state descriptor/single-link/stability policy, ordinary protected-file denial, DPAPI mechanism behavior, real-dependency broker startup composition through injected protected-state/listener seams, SCM state/retry/stop ownership through an injected runtime, fixed service-registration policy/drift/rollback through synthetic and injected dependencies, create-new installer ordering/receipt/credential/rollback through injected dependencies, an actual built broker image policy check, a read-only native fixed-service query, native interactive-context and non-LocalSystem TokenUser denial, real temporary-directory workload-ACL convergence/rollback, real local named-pipe descriptor/authentication/framing behavior, current-token artifact collection/handle stability/hard-link/quota behavior, platform-neutral response framing/digest/transaction cleanup behavior, and current-peer authenticated session composition with fake execution internals.

They do not prove successful elevated protected-root convergence, account creation, effective logon-right assignment, service registration/descriptor/recovery mutation, composite native installation, LocalSystem service behavior, or effective installed execution-account access/denial. The service probe is read-only and makes no registration claim. The pipe test treats the current process as the synthetic control SID; it does not prove installed control success, installed execution/unrelated-user denial, non-control administrator rejection, or remote-host rejection. Artifact tests likewise use the current token and do not prove allowed/denied reads by installed execution identity; the local reparse test can skip without symbolic-link privilege. The workload-ACL tests use a nonexistent synthetic SID under fresh temporary directories and restore/remove their own state. The native account package performs only a real absent-name query during ordinary tests; all mutating account/LSA/service/composite and installed-token evidence is a later isolated-smoke gate. Cross-compilation is not Windows security evidence.
