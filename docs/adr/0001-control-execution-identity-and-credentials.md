# ADR 0001 — Control, Execution Identity, and Credential Boundary

- Status: Accepted
- Date: 2026-09-02
- Scope: local authority separation and the credentials that cross, or must not cross, that boundary

## Context

Agent Workstation Gateway (AWG) deliberately lets a remote agent request development work on a real workstation. The remote requester can therefore ask for destructive commands inside development data that the workstation owner has explicitly authorized.

That intentional authority must not silently become authority over:

- the self-hosted runner;
- the private control workflow;
- gateway installation or security policy;
- GitHub management credentials;
- the human user's credentials;
- unrelated workstation files;
- an arbitrary administrator/root execution API.

The threat model requires the public source repository to have zero persistent workstation authority and requires a private control repository. This ADR decides the local identity boundary and the credential ownership model that make those properties enforceable.

## Decision

AWG uses four distinct principals/roles:

1. **workstation administrator** — installs, updates, repairs, changes approved roots/capabilities, and uninstalls AWG;
2. **remote requester** — can submit bounded requests and read results through the selected private GitHub transport; its credential remains outside the workstation and does not receive repository-source, workflow-source, runner-management, secrets-management, or repository-administration authority by default;
3. **control/runner identity** — a dedicated non-administrator local OS identity that runs the GitHub self-hosted runner and the fixed control workflow;
4. **execution identity** — a dedicated restricted non-administrator local OS identity under which arbitrary requested workloads execute.

A fifth component is a **privileged local broker**:

- Windows: a LocalSystem service;
- Linux: a root system service.

The broker is not a fifth human/service authority. It is a narrow local privilege separator. It has **no GitHub credential** and exposes no generic privileged shell, run-as-user, ACL-management, account-management, or service-management API to the runner.

The normal authority path is:

```text
remote requester
  |  least-privilege GitHub request transport
  |  exact remote permission set decided separately
  |  no local runner/broker credential
  v
private fixed control workflow / event handler
  |  runs as dedicated control/runner OS identity
  |  owns job-scoped GITHUB_TOKEN and runner state
  v
privileged local broker
  |  authenticated local IPC
  |  validates policy and constructs launch
  v
restricted execution identity
  |  approved development roots only
  |  allowlisted environment
  |  optional capabilities only when explicitly enabled
  v
requested workload
```

## Remote GitHub requester credential

This ADR decides where the remote credential may exist and what it must never become; it deliberately does **not** freeze the final GitHub event transport.

A credential that can write arbitrary files in the private control repository is too powerful for the desired boundary. Even if workflow-source edits are separately denied, repository write access could let a compromised requester rewrite request/result records or modify data that a future control workflow might accidentally treat as executable code.

Non-negotiable properties for the eventual requester credential are:

- it is stored and used on the remote agent side, never on the workstation;
- it is scoped to one private control repository;
- it receives no repository-administration, Secrets, or runner-management authority;
- it receives no workflow-source write authority;
- repository Contents write is not part of the default design;
- a coarse provider permission is not described as narrower than it actually is;
- request size, shape, replay, and concurrency are bounded by the AWG protocol rather than by GitHub's maximum payload alone.

`workflow_dispatch` remains a candidate transport, but is not accepted here as a "dispatch-only" grant. GitHub currently requires **Actions: write** to create a workflow-dispatch event, and the same Actions permission class is also used by workflow-management endpoints such as enable/disable and re-run operations. The dispatch API also accepts a caller-supplied branch or tag `ref`. Those facts make `Actions: write` materially broader than a dedicated submit-request permission.

A later private-control transport ADR must compare the practical GitHub options, including a fixed default-branch event transport and `workflow_dispatch`, choose the least-privilege credential model, define authoritative result/tamper semantics, and record any unavoidable residual authority. None of those transport choices may collapse the local broker/execution boundary decided here.

## Fixed control workflow rules

The private control workflow is executable control-plane code and is installed only into the private control repository.

It must:

- exist only in the private control repository, never as an active self-hosted workflow in the public source repository;
- accept request data only through the selected control event/transport and parse the event payload strictly as data;
- never interpolate untrusted request data into shell source;
- pass request data to an installed, protected AWG control executable as data;
- never execute scripts, binaries, hooks, configuration, or other mutable code from the private control repository;
- preferably avoid repository checkout entirely;
- if checkout is ever required, set `persist-credentials: false`, keep submodules disabled unless explicitly required, and treat all checked-out content as untrusted data;
- materialize the accepted request and authoritative result using only the job-scoped GitHub authority required by the selected transport;
- use minimum workflow token permissions, normally only the repository-content permission needed to publish the durable ledger;
- never forward the runner process environment to the broker.

The installed local AWG binaries and security policy are administrator-owned local files. A requester cannot replace them by changing private-repository content.

## Credential ownership

| Credential or secret | Owner / location | Available to arbitrary workload? |
|---|---|---|
| Human GitHub/browser/SSH/cloud credentials | human profile only | No |
| Installer/bootstrap GitHub credential | interactive installer process only | No |
| Runner registration token | transient bootstrap only | No |
| Runner registration/state files | control/runner identity | No |
| Job-scoped `GITHUB_TOKEN` | control workflow process | No |
| Remote requester transport token/App grant | remote agent platform, never workstation | No |
| Broker local execution-account secret on Windows | broker-protected local state | No |
| Optional workload Git credential | execution identity profile, explicit opt-in | **Yes, by design** |
| Docker/privileged daemon capability | disabled by default | No by default |

The broker does not receive, persist, or request GitHub tokens.

The base installation provides no private Git credential to the execution identity. If a user explicitly configures a credential so workloads can clone or push private repositories, that credential is considered readable and exfiltratable by arbitrary workloads running as the execution identity. It must therefore be a separate least-privilege workload credential, never a human credential and never a control-plane credential.

## Control/runner identity

The GitHub self-hosted runner runs under a dedicated local non-administrator identity, conceptually `awg-control`.

That identity owns or can read:

- the runner installation and registration state;
- the private control workflow working area, if one is needed;
- job-scoped GitHub credentials supplied by GitHub Actions;
- the client side of the broker control IPC.

It does **not** receive administrator/root privileges and does not directly execute arbitrary requested workloads.

A compromise of the fixed control job can therefore request arbitrary work within the broker's configured execution authority, but it cannot ask the broker to run as root/LocalSystem, change approved roots, create users, edit service configuration, or read broker secrets.

## Privileged local broker

The broker exists because switching from the runner identity to a different restricted OS identity requires privileged local operations on both Windows and Linux.

The broker has two trust surfaces:

### Normal control surface

Accessible only to the dedicated control/runner identity (plus local administrators for diagnostics). It supports the execution protocol only.

It may:

- validate protocol/version/size limits;
- validate a requested working directory against administrator-configured approved roots;
- validate allowed request environment additions;
- create a sanitized environment;
- launch a process as the fixed execution identity;
- own process-lifecycle metadata and timeout/cancellation control;
- capture exit/timeout metadata and stdout/stderr as untrusted data;
- coordinate artifact collection under execution authority.

It may **not**:

- choose an arbitrary run-as identity;
- run a command as the broker/control identity;
- edit approved roots or optional capabilities;
- edit ACLs/ownership on requester-supplied paths;
- install/update/remove services;
- create/delete accounts through the normal IPC;
- reveal execution-account credentials;
- return arbitrary root/SYSTEM-readable files;
- accept a caller-supplied inherited environment.

### Administrative surface

Installation, update, repair, root/capability changes, and uninstall are local elevated operations. They are not methods on the runner-facing control protocol.

Administrator-owned configuration is stored outside approved development roots and is not writable by either the control or execution identity. The broker may converge privileged local state from that protected configuration during service startup/repair, but the private control repository cannot change it.

## Execution identity

Arbitrary requested commands always run under a dedicated restricted identity, conceptually `awg-exec`.

Default properties:

- local non-administrator account;
- no interactive human session requirement;
- dedicated profile/home, temporary directory, caches, and tool state;
- no membership in administrator/root-equivalent groups;
- no membership in Docker or another privileged-daemon group by default;
- no access to runner files, private control state, broker configuration/secrets, or the human profile;
- filesystem access only to approved development roots and explicitly enabled supporting paths;
- no generic sudo/admin elevation;
- no control-IPC authorization.

All ordinary child processes and explicitly persistent development processes use this same execution authority unless a future ADR introduces a stronger per-workload isolation mode.

## Windows design

### Broker identity

The broker runs as a Windows service under **LocalSystem**.

LocalSystem is intentionally privileged because the broker must create a process in another security context and may need to load the execution user's profile. Microsoft documents that `CreateProcessAsUser` typically requires `SeIncreaseQuotaPrivilege` and may require `SeAssignPrimaryTokenPrivilege`; LocalSystem services hold the privileges needed for this server-side pattern. `LoadUserProfile` also requires an administrator or LocalSystem caller on supported Windows versions.

The security consequence is explicit: a memory-safety or logic vulnerability in the broker is a local privilege-escalation risk. The broker implementation must therefore be small, typed, strictly parsed, and free of generic privileged command execution.

### Execution account and token

The installer/broker provisions a dedicated local standard account for `awg-exec`.

For the initial implementation:

1. privileged broker initialization generates a high-entropy random local-account password;
2. the broker creates or repairs the gateway-owned execution account;
3. the account is granted `SeBatchLogonRight` and is denied interactive/remote-interactive use where policy permits;
4. the broker protects the generated secret with Windows DPAPI **under the LocalSystem user scope** and stores only ciphertext in a SYSTEM/administrators-only broker state directory;
5. `CRYPTPROTECT_LOCAL_MACHINE` is not used, because Microsoft documents that machine scope allows any user on the same machine to decrypt data protected with that scope;
6. for a request, the broker decrypts the secret only into short-lived memory, calls `LogonUserW` using `LOGON32_LOGON_BATCH`, immediately zeroes plaintext buffers, and closes tokens/secret buffers as soon as possible;
7. the resulting primary token is used with `CreateProcessAsUserW`;
8. if user-profile state is required, the broker uses `LoadUserProfile` and keeps the profile lifetime bounded to owned execution activity.

The account secret is a launch mechanism, not a workload credential. It is never written into the execution environment, command line, logs, results, or files readable by `awg-exec`.

The broker, not an interactive installer user, performs the DPAPI protection step so the ciphertext is bound to the broker's LocalSystem DPAPI identity.

Domain/group policy can override local logon rights. `doctor` must perform an actual non-secret batch-logon/probe before reporting Windows execution ready.

### Windows environment construction

`CreateProcessAsUser` uses the caller's environment if `lpEnvironment` is `NULL`, which would leak broker/control context.

AWG therefore never passes `NULL` for the workload environment.

The broker may use `CreateEnvironmentBlock(token, FALSE)` to obtain non-inherited system/user values, but it then projects those values through an explicit allowlist and overwrites gateway-owned profile/temp/path values. Request-supplied additions are independently validated against protocol policy.

GitHub/Actions variables, runner variables, management tokens, human-session variables, and broker secrets are not copied.

### Windows IPC

The normal control endpoint is a local named pipe.

Required properties:

- an explicit security descriptor/DACL is supplied; the default named-pipe DACL is forbidden because Microsoft documents default read access for Everyone and anonymous users;
- the DACL grants only LocalSystem, local administrators, and the configured `awg-control` SID the required access;
- the execution SID is not granted access;
- `PIPE_REJECT_REMOTE_CLIENTS` is enabled;
- after connection/message receipt, the broker calls `ImpersonateNamedPipeClient`, checks the return value, obtains the caller token/SID, and requires the configured control SID for normal execution requests; administrator access to the pipe is diagnostic only and does not bypass that authorization check;
- after identity inspection the broker always calls `RevertToSelf`; if reversion fails, the broker terminates rather than continuing under a client token;
- client process ID may be logged for diagnostics but is not an authorization primitive;
- every authentication/impersonation failure is fail-closed.

The pipe accepts bounded protocol data, not shell text to execute as LocalSystem.

## Linux design

### Broker and accounts

The broker runs as a root-owned systemd system service. The runner and workload use two different static local identities, conceptually `awg-control` and `awg-exec`.

The accounts have no general sudo capability. The execution identity is not a member of the control IPC group and is not a member of `docker` by default.

### Linux IPC

The normal control endpoint is a filesystem AF_UNIX stream socket, preferably systemd socket-activated.

Required properties:

```ini
SocketUser=root
SocketGroup=awg-control-ipc
SocketMode=0660
```

The execution user is never a member of `awg-control-ipc`.

`SocketMode` is explicit because systemd's documented default for filesystem sockets is `0666`.

Filesystem permissions are only the first check. After `accept`, the broker uses `SO_PEERCRED` and requires the peer UID to equal the configured control UID. The peer credentials are those associated with the connected process at connection time. A mismatch is rejected before protocol processing.

An abstract-namespace Unix socket is not used for this authorization boundary because the filesystem socket's owner/group/mode provide an independent access-control layer.

### Linux child privilege drop

For each launch the root broker creates a child/process context and, before arbitrary `execve`:

1. resolves the fixed execution UID/GID from protected configuration;
2. sets supplementary groups to an explicit configured allowlist (empty except gateway-required groups by default); it does not blindly inherit the broker's groups;
3. sets real/effective/saved GID to the execution GID;
4. does not enable keep-capabilities or set-UID-fixup bypasses, then sets real/effective/saved UID to the nonzero execution UID;
5. verifies the resulting real/effective/saved UID/GID and supplementary groups, and verifies that permitted, effective, and ambient capability sets are empty before arbitrary `execve`;
6. sets the Linux no-new-privileges flag so a later `execve` cannot gain privilege from set-ID bits or file capabilities;
7. installs the broker-constructed allowlisted environment;
8. changes/enters the validated working directory under execution authority and executes the requested program.

No broad sudoers rule and no requester-controlled `sudo`, `su`, `setpriv`, or arbitrary `systemd-run` command is part of the control protocol.

systemd service hardening such as `NoNewPrivileges=`, `ProtectSystem=`, `ProtectKernelTunables=`, and related settings should be enabled where they are compatible and actually verified. They are defense in depth, not substitutes for the UID/GID and socket boundary. systemd explicitly notes that some filesystem-namespace protections may be unavailable in containers or unsupported environments and that read-only path controls do not themselves block AF_UNIX IPC.

## Approved development roots

Approved roots are local administrator-owned configuration, never request data from GitHub.

For every request the broker:

1. canonicalizes the requested working directory as close as possible to launch time;
2. proves it lies beneath an approved root;
3. rejects traversal and link/reparse escape according to platform rules;
4. relies on OS ACL/ownership permissions as the final boundary if a path changes after validation;
5. launches the workload as `awg-exec`, so even a successful path race does not grant the broker's root/SYSTEM filesystem authority.

The broker must avoid implementing artifact collection by reading arbitrary requester paths as root/SYSTEM. Artifact enumeration/content access runs under execution authority or an equivalently restricted child, then trusted broker/control code records hashes/metadata and publishes the bounded result.

Exact Windows ACL and Linux ownership/ACL provisioning is a platform implementation decision, but the effective access tests are release gates.

## Result authority

The execution process owns only its stdout/stderr bytes and files it can create under execution authority. Those are untrusted data.

The broker owns trusted local execution metadata such as:

- validated request identifier;
- start/finish time;
- process exit/timeout/cancellation state;
- bounded output capture metadata;
- artifact-policy decisions.

The fixed control workflow/event handler owns authoritative publication using only the job-scoped GitHub authority required by the selected transport.

`awg-exec` cannot read or write private control state. The eventual remote transport must either prevent the requester credential from rewriting authoritative results or make control-produced results verifiably distinguishable from requester-authored data. Exact GitHub storage/signing semantics are a later control-transport decision; arbitrary workload never receives publication authority.

## Optional powerful capabilities

Docker and similar local daemons are capability grants, not ordinary tools.

They are disabled by default. Enabling one is an administrator-owned local configuration change and may add the execution identity to a privileged group or grant a specific socket/device permission. The doctor output must make such grants visible, and documentation must state their host-equivalent implications where applicable.

A control request cannot enable a capability for itself.

## Rejected alternatives

### Runner executes arbitrary work as its own identity

Rejected. It collapses the runner's GitHub credentials, private control state, and arbitrary workload into one principal.

### A long-lived execution daemon runs as the same identity as arbitrary workloads

Rejected as the privilege boundary. Workloads sharing that UID/SID can often interfere with same-user processes and state. The broker must reside in a different, more privileged identity and expose only the narrow launch protocol.

### Direct `runas`, broad sudo, or generic privileged helper

Rejected. These either require unsuitable credential handling or create a general privilege-escalation surface. The privileged component must understand AWG's bounded execution policy and always choose the fixed execution identity.

### Containers/Docker as the primary workstation boundary

Rejected for the base architecture. Docker access is itself host-powerful on common Linux installations, and container-first execution does not preserve the expected native workstation filesystem/tool semantics. Containers remain useful for disposable cross-distribution testing.

### Per-request OS accounts

Deferred. Per-request identities could provide stronger isolation between workloads, but they add substantial account lifecycle, filesystem ACL, cache/toolchain, and cleanup complexity. The fixed `awg-exec` identity is the v0.1 boundary; stronger modes can be added without merging it with control authority.

### Give requester `Contents: write` but deny `Workflows: write`

Rejected for the default design. Preventing workflow edits alone is insufficient if control jobs ever consume mutable repository scripts/configuration or if request/result integrity matters. Request submission must not require arbitrary repository-content write authority.

### Treat `Actions: write` as a dispatch-only permission

Rejected as an assumption. GitHub requires Actions write for `workflow_dispatch`, but that permission class covers other workflow operations as well and dispatch accepts a caller-selected branch or tag reference. `workflow_dispatch` may still be selected later, but only with its real residual authority documented and constrained by a dedicated control-repository design.

### Let the fixed control workflow execute checked-out repository code

Rejected. That would turn any content-writing capability into code execution under the control/runner identity. Repository data is never a source of executable control-plane code.

### Store the Windows execution-account password in plaintext

Rejected. The password is broker-only launch material and is protected at rest. DPAPI machine scope is also rejected because it is too broad for the intended account separation.

## Consequences

### Benefits

- A compromised or mistaken workload cannot automatically read GitHub control credentials or human credentials.
- A compromised requester credential can submit destructive work only within configured execution authority; the local broker boundary still prevents it from becoming root/LocalSystem or replacing protected local gateway code. Transport-level audit/availability authority depends on the later GitHub transport decision and must be bounded separately.
- Windows and Linux share the same conceptual authority model despite different native mechanisms.
- The broker has no cloud credential to steal.
- Security-critical local configuration remains outside GitHub request data.
- Result publication remains separate from arbitrary workload authority.

### Costs

- Installation requires elevated local provisioning and platform-specific account/IPC/service code.
- The privileged broker becomes a security-critical local component and must be aggressively minimized and tested.
- Windows requires careful execution-account secret lifecycle and token/profile handling.
- GitHub's built-in permission classes are coarse enough that the final request transport needs its own ADR and negative permission tests.
- A single fixed execution account isolates workloads from control authority, not from each other across time; cleanup and optional stronger isolation remain necessary.
- Explicit workload credentials and Docker access reduce the boundary by design and require visible opt-in.

## Verification requirements

The design is not considered implemented until automated or isolated smoke tests demonstrate, without printing secret values:

### GitHub/control transport

- the selected requester credential can submit one bounded request and read its result using only the documented transport permissions;
- requester credential cannot write gateway/control source, modify workflow source, manage runners/secrets, or administer the repository;
- every broader provider permission required by the chosen transport is documented and negative-tested instead of being described as narrower than it is;
- authoritative control-produced results cannot be silently forged by arbitrary workload; if requester-authored records are mutable, control origin/tamper evidence is independently verifiable;
- public source repository has no active self-hosted workflow;
- fixed private control workflow/event handler does not execute mutable repository code;
- any checkout that is introduced explicitly disables persisted credentials.

### Common local boundary

- control identity can connect to broker control IPC;
- execution identity cannot connect;
- workload cannot select another run-as identity;
- workload cannot change approved roots/capabilities;
- synthetic GitHub/Actions/management markers are absent from workload environment;
- workload can read/write a synthetic approved root;
- workload is denied a synthetic control file and synthetic human-secret file;
- workload cannot write broker binaries/configuration;
- broker result metadata cannot be overwritten by the execution identity.

### Windows

- named-pipe DACL is explicit and rejects the execution identity;
- remote pipe clients are rejected;
- peer SID verification is fail-closed;
- `LOGON32_LOGON_BATCH` succeeds for the synthetic execution account;
- interactive/remote-interactive execution account logon is denied where configured;
- the execution account cannot read broker DPAPI ciphertext/state;
- plaintext account secret never appears in environment, command line, stdout/stderr, or logs;
- workload environment is demonstrably non-inherited.

### Linux

- control socket mode/owner/group match policy;
- `SO_PEERCRED` UID verification rejects the execution user;
- arbitrary child runs with expected UID/GID/supplementary groups and no new privileges;
- execution user has no sudo and no Docker group by default;
- systemd hardening claims are based on inspected effective configuration and host behavior, not unit-file text alone.

## References

Authoritative sources reviewed for this decision:

### GitHub

- GitHub Docs — Adding self-hosted runners: https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/add-runners
- GitHub Docs — Secure use reference: https://docs.github.com/en/actions/reference/security/secure-use
- GitHub Docs — REST API endpoints for workflows (`workflow_dispatch` permissions): https://docs.github.com/en/rest/actions/workflows
- GitHub Docs — Workflow syntax (`workflow_dispatch` input limits): https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax
- GitHub Docs — Events that trigger workflows (default-branch event semantics): https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows
- GitHub Docs — Choosing permissions for a GitHub App: https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app
- `actions/checkout` current action definition (`persist-credentials` defaults to true): https://github.com/actions/checkout/blob/main/action.yml

### Windows

- Microsoft Learn — `LogonUserW`: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw
- Microsoft Learn — `CreateProcessAsUserW`: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw
- Microsoft Learn — `CreateEnvironmentBlock`: https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-createenvironmentblock
- Microsoft Learn — `LoadUserProfileW`: https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-loaduserprofilew
- Microsoft Learn — `CryptProtectData`: https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata
- Microsoft Learn — Named Pipe Security and Access Rights: https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
- Microsoft Learn — `CreateNamedPipeW`: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipew
- Microsoft Learn — `ImpersonateNamedPipeClient`: https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- Microsoft Learn — `NetUserAdd`: https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuseradd
- Microsoft Learn — Log on as a batch job (`SeBatchLogonRight`): https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/log-on-as-a-batch-job

### Linux

- Linux man-pages — `unix(7)` / `SO_PEERCRED`: https://man7.org/linux/man-pages/man7/unix.7.html
- Linux man-pages — `systemd.socket(5)` (`SocketUser`, `SocketGroup`, `SocketMode`): https://man7.org/linux/man-pages/man5/systemd.socket.5.html
- Linux man-pages — `systemd.exec(5)` (`User`, `NoNewPrivileges`, filesystem hardening caveats): https://man7.org/linux/man-pages/man5/systemd.exec.5.html

## Follow-up decisions

This ADR intentionally does not select the implementation language or executable packaging. A separate ADR must select the cross-platform implementation/runtime after evaluating how safely it can implement the native boundaries described here.

The GitHub request/result transport and exact remote requester permission set are a separate bounded decision. Protocol details, exact filesystem ACL recipes, process-group/job-object lifecycle, update/signing, and the isolated smoke-lab topology are also separate decisions. They may strengthen this ADR but must not collapse the control/execution identity boundary.
