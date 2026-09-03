# Windows Implementation and Installation State

Windows x64 is a supported AWG v0.1 target. It uses native path, token, Job Object, protected-state, account/right, ACL, named-pipe, SCM service, runner, artifact, and private-control mechanisms; the complete boundary has inspected isolated-host E2E evidence.

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

The CLI invokes the create-new account transaction through an elevated native boundary. Both configured names must be absent before password generation. It generates independent mutable credentials, creates only normal local users, resolves their real SIDs, and binds those SIDs into installed configuration.

Both accounts must have built-in Users as their only reported local-group membership. Their recorded token primary group is the distinct account-domain Users SID. Control receives service logon plus interactive/RDP deny rights. Execution receives batch logon plus interactive/RDP/service deny rights. The right strings and memberships are product policy, not installer input. [ADR 0008](adr/0008-windows-local-account-and-logon-right-provisioning.md) records the exact sets and create-new decision.

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

The native store creates gateway-owned directories and files with Builtin Administrators ownership and a protected LocalSystem/Administrators-only DACL. Using the administrator owner is required for direct creation by an elevated installer; assigning LocalSystem as creator-time owner is rejected by Windows. It opens directories/files with `FILE_FLAG_OPEN_REPARSE_POINT`, compares same-handle final paths, and rejects aliases or reparse points.

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

Background `start`, `status`, `logs`, and `stop` operations use the same authenticated session path and restricted Windows launcher. Their in-memory registry is keyed by session/process ID, capped at 32 entries, checks the original canonical working directory, and retains only bounded stdout/stderr prefixes. `start` keeps the Job Object and execution-token/profile lease owned by the broker; `stop`, lifetime expiry, service shutdown, and process exit synchronously reap the full job. See [ADR 0020](adr/0020-bounded-background-process-lifecycle.md).

The Windows broker host now loads only exact protected state paths derived from the installation root, denies overlap with every execution-owned root, obtains the Windows directory through the native API instead of copying the service environment, and composes the real token/launcher/collector/session/listener graph without a current-user fallback. Credential protection is revalidated on every acquisition. Each accepted connection is closed after one session. See [ADR 0014](adr/0014-windows-broker-startup-composition.md).

## SCM broker lifecycle

`awg-broker.exe` is now a service-only binary with the fixed SCM name `AgentWorkstationGatewayBroker`. Its image command line accepts only the administrator-protected installation root. The exact public source commit is embedded by trusted release builds; an empty, uppercase, symbolic, or otherwise non-lowercase-40-hex source value fails startup. There is no interactive console fallback.

## Fresh install command

The mutating Windows installer is run from an elevated terminal with an authenticated GitHub CLI session. It accepts only pinned local release inputs, uses `gh auth token` through a bounded pipe rather than a command argument, and supports either creating a new initialized personal private repository or selecting an existing one:

For v0.1, download `actions-runner-win-x64-2.337.0.zip` only from the official [`actions/runner` v2.337.0 release](https://github.com/actions/runner/releases/tag/v2.337.0). Before installation require an exact size of `103528051` bytes and SHA-256 `1150692afa94e71f872017e254ea55b6eece1eece3fe7e3a6d4c93d0a1b85cfc`. Verify the AWG archive and hosted control helper against the release's `SHA256SUMS` before elevation.

```powershell
.\awg.exe install `
  --spec .\windows-install.json `
  --repository alice/example-control `
  --create-repository `
  --broker-image .\awg-broker.exe `
  --control-image .\awg.exe `
  --runner-archive .\actions-runner-win-x64-2.337.0.zip `
  --hosted-control-url https://github.com/eldenizfamilyanskicode/agent-workstation-gateway/releases/download/v0.1.0/awg-control_0.1.0_linux_amd64 `
  --hosted-control-sha256 <digest-from-SHA256SUMS>
```

Release builds embed the exact 40-hex public source SHA in both Windows executables. The installer rejects a broker or control executable that is not an AMD64 PE image containing that SHA, and independently enforces the fixed v0.1 GitHub runner version, exact archive byte count, and SHA-256.

The selected repository must be owned by the authenticated personal account, private, and have no other effective collaborator. v0.1 rejects organization repositories and shared personal repositories because their reader/requester boundary requires an explicit policy not yet represented by this command. There is no public-repository override.

Bootstrap creates or confirms only `.github/workflows/execute-request.yml` and `control-version.json`. Existing differing content is a hard conflict. It then requests short-lived registration/removal tokens, commits the create-new local account/ACL/service/runner transaction, installs the verified execute-only client under the control identity's protected runner root, and starts the fixed broker and runner services. The private workflow uses a process-local execution-policy override for its fixed control step so it does not require a machine-wide PowerShell policy change. The client can reach the authenticated broker pipe but cannot read the administrator-only gateway state. A failure never prints a token, issue body, private local path, or GitHub response body.

Run health checks with the matching installed binary:

```powershell
C:\ProgramData\AgentWorkstationGateway\bin\awg.exe doctor --installation-root C:\ProgramData\AgentWorkstationGateway
```

Doctor reads only fixed protected files, validates both account identities and exact logon rights, approved/isolated-root ACL policy, protected runner credentials, exact service configuration/DACLs and running state, then revalidates private visibility, the exclusive reader boundary, the registered runner identity, and both fixed control-file digests. Its JSON output reports the build version, exact source SHA, and boundary booleans; it never displays credential or runner-state contents. `awg.exe version` reports the same release identity without inspecting installed state.

Uninstall must be invoked from the matching release executable outside the protected installation root because Windows cannot remove the currently executing installed image:

```powershell
.\awg.exe uninstall --installation-root C:\ProgramData\AgentWorkstationGateway
```

Uninstall preflights all protected local state and remote ownership before mutation. It stops both services, removes only the exact labeled repository runner and installer-created control files whose digests still match, deletes the fixed services, removes the protected runner/install roots and create-owned profile/temp roots, revokes only the installed execution SID from approved development roots, and finally deletes the two exact local accounts. It preserves the private repository, ledger, README, control files that predated installation, development files, and unrelated local paths. A changed or extra protected-root object fails closed instead of being recursively removed.

For an upgrade, run `doctor`, uninstall with the matching old external release binary, verify the new release checksums, and install the new release with the same reviewed specification and private repository. The ledger and development files remain; execution is offline during the transition. Finish with `doctor` and one minimal request. See [ADR 0022](adr/0022-v0.1-release-and-upgrade.md).

Before protected-state loading, the service requires an actual SCM process context and exact LocalSystem TokenUser. It reports bounded StartPending/Running/StopPending states and accepts only Stop/Shutdown. Shutdown cancels execution, closes the listener and any active connection to interrupt IPC, and waits for the owned sequential loop. Only closed peer/session failures continue to another accept; listener infrastructure and handle-close failures terminate the service. See [ADR 0015](adr/0015-windows-scm-broker-service.md).

The binary can be built for inspection with a synthetic source value:

```powershell
go build -ldflags "-X main.gatewaySourceSHA=0123456789abcdef0123456789abcdef01234567" ./cmd/awg-broker
```

This does not install or start the service.

The native service-registration boundary now accepts only the canonical installation root. It derives the fixed protected broker path and exact argument, requests only SCM connect/create rights, and checks a possible pre-existing fixed service with query-only access. A collision fails closed without adoption or deletion.

Creation is staged disabled. SCM supplies the LocalSystem owner/group; the installer applies only the exact protected DACL granting full service access to LocalSystem and Builtin Administrators, then independently verifies owner, group, and DACL. Recovery permits restarts after 5 and 30 seconds followed by no action, has no command or reboot behavior, and resets after 24 hours. Automatic start is applied last, then configuration, recovery, and descriptor state are queried independently. An uncommitted lease deletes only a service positively created by that lease. See [ADR 0016](adr/0016-windows-broker-service-registration.md).

## Create-new installer transaction

The Windows composite installer now pins a strict specification, canonical source SHA, and trusted bounded PE32+ AMD64 broker image before mutation. The image must contain the build-embedded exact SHA and cannot be a DLL. This does not authenticate downloaded bytes: release/bootstrap code must still verify published artifact provenance before invoking the transaction.

The fixed sequence performs a read-only service collision query, creates accounts and binds their SIDs, converges workload filesystem leases, creates a new protected root/image/state, clears the execution password after DPAPI materialization, and finally registers the verified service. No spec/request field chooses the broker destination, protected state paths, service policy, account rights, or stage order.

One uncommitted lease owns reverse cleanup: service, exact known protected files and empty directories, filesystem changes, then accounts. It refuses to adopt an existing installation root and never recursively deletes unknown content. A temporary copy provides the control password only to a later synchronous trusted runner-service consumer and is cleared on return. The account-owned original remains until the larger setup commits or rolls back. See [ADR 0017](adr/0017-windows-create-new-installer-transaction.md).

## Bounded artifact collection

Post-command artifact selection is implemented as execution-authority filesystem access, not a LocalSystem file proxy. The collector validates the token's exact execution user/primary group, pins and impersonates that token, then opens the configured root, working directory, and matched files before reverting. Root/working handles require exact final paths; candidates must be regular single-link disk files with no reparse attribute and a final path still beneath both guards.

Portable case-sensitive slash globs support recursive `**`. Enumeration skips sensitive segments and is capped at 8,192 entries and 32 segments deep. Protocol limits cap the result at 256 files, 512 MiB per file, and 1 GiB total. Size is checked before hashing. Each file remains held by the same one-shot handle used for SHA-256, with write/delete sharing denied until the reader or bundle closes.

The platform-neutral response layer now streams those exact handles in manifest order through 64 KiB frames and requires exact size/SHA-256 at both ends. Retained stdout/stderr receive separate prefix hashes because report hashes cover complete streams even when their returned prefixes are truncated. A control-side artifact transaction commits only after all content, the completion handshake, and terminal EOF validate; otherwise it aborts.

`awg execute-local --accepted <path> --attempt <id> --output <path>` now owns the Windows client side. The output parent is trusted control policy and must already be a protected runner directory; it is never selected by request data. The client stages create-new files, rejects reparse parents, aliases, reserved names, collisions, and incomplete transactions, then publishes `execution-report.json`, `stdout.bin`, `stderr.bin`, and `artifacts/` with one directory rename only after response/attempt binding passes. This local response is still non-authoritative until a later hosted finalizer validates and publishes it. See [ADR 0011](adr/0011-windows-execution-authority-artifacts.md), [ADR 0012](adr/0012-bounded-local-broker-response-stream.md), and [ADR 0018](adr/0018-windows-control-client-response-publication.md).

## Evidence limits

The v0.1 Windows acceptance matrix exercised elevated create-new installation, real dedicated accounts/SIDs and logon rights, protected state and runner credentials, SCM services and DACLs, LocalSystem-to-execution-token launch, named-pipe authentication, approved/denied filesystem access, environment and credential denial, foreground/background execution, timeout/stop process-tree cleanup, output/artifacts, private hosted transport, doctor, uninstall, ACL restoration, and reinstall on an isolated Windows x64 host. Public CI separately runs Windows-native tests and cgo-free builds.

This evidence is specific to the inspected host and release commit. It does not make AWG a malware sandbox, prove every Windows policy/domain configuration, or replace operator review of approved roots and optional tools. Cross-compilation alone remains build evidence only.
