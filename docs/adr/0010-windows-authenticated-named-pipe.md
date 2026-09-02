# ADR 0010 — Windows Authenticated Named-Pipe IPC

- Status: Accepted
- Date: 2026-09-03
- Scope: Local control-to-broker transport on Windows

## Context

The broker runs with LocalSystem authority while its normal client runs as the dedicated non-administrator control identity. A default named-pipe descriptor is not acceptable: Windows grants default read access to Everyone and anonymous users. A DACL check alone is also insufficient because LocalSystem and Administrators need operational access to the pipe but must not acquire permission to submit normal execution requests.

The local transport carries only the execute-only broker envelope. Pipe name, modes, buffers, principals, access masks, and peer authorization are installed product policy; none are request fields.

## Decision

Windows uses the fixed local endpoint `\\.\pipe\agent-workstation-gateway-v1`. The server creates one message-mode, overlapped instance with `FILE_FLAG_FIRST_PIPE_INSTANCE` and `PIPE_REJECT_REMOTE_CLIENTS`. The first-instance flag turns a pre-existing endpoint into a startup failure instead of silently joining an attacker-created pipe namespace. Accept and dial operations are context-cancellable, and close cancels pending native I/O before releasing its handle.

Every created server handle is queried with `GetSecurityInfo`. The resulting DACL must be protected, contain exactly three non-inherited allow ACEs, and contain no other ACE type or principal:

| Principal | Exact access |
|---|---|
| LocalSystem | Windows `FILE_ALL_ACCESS` (`0x1f01ff`) |
| built-in Administrators | Windows `FILE_ALL_ACCESS` (`0x1f01ff`) |
| configured control SID | `FILE_GENERIC_READ | FILE_GENERIC_WRITE`, excluding `FILE_APPEND_DATA` (`0x12019b`) |

For named pipes `FILE_APPEND_DATA` and `FILE_CREATE_PIPE_INSTANCE` have the same numeric value. It is deliberately removed from the control ACE and the client's requested access, so the control identity can exchange duplex data but cannot create a server instance. The configured execution SID, Everyone, anonymous users, and all other principals are absent.

Each client opens the fixed name with Security Identification quality-of-service and sends one fixed four-byte authentication preface. The preface is necessary because `ImpersonateNamedPipeClient` uses the security context of the last message read by the server. It carries no operation or requester-controlled policy.

After reading that preface and before returning the connection for envelope framing/decoding, the server:

1. pins the goroutine to its current OS thread;
2. requires `ImpersonateNamedPipeClient` to succeed;
3. opens the thread token with `OpenAsSelf=TRUE` and reads `TokenUser`;
4. requires that SID to exactly equal the installed control SID—membership in Administrators is not an authorization bypass;
5. calls `RevertToSelf` before the connection can expose envelope bytes.

Any failure closes the connection. If `RevertToSelf` fails, the process exits with a fixed software-failure status rather than risking continued LocalSystem broker work under a client token.

Application records use the shared four-byte big-endian framing contract. Zero-length, truncated, and oversized records are rejected before an attacker-sized allocation. The maximum record size is 256 KiB and the pipe buffers are bounded to that record plus its header.

## Alternatives considered

### Use the default named-pipe descriptor

Rejected. It grants documented default access to broad and anonymous principals and cannot express the configured control identity boundary.

### Authorize any DACL-admitted administrator

Rejected. Administrative pipe access exists for service operation and diagnostics, not as a normal execute permission. The impersonated TokenUser must still be the exact control SID.

### Grant `GENERIC_WRITE` to the control client

Rejected. Its named-pipe mapping includes the create-instance bit. AWG requests the required individual rights and excludes that bit.

### Impersonate before reading any client data

Rejected. Windows defines the impersonated context as the client context associated with the last message read. The fixed preface establishes that context without decoding an execution request first.

## Consequences and evidence limits

Ordinary Windows tests create a real local pipe, query and validate the real descriptor during server construction, exchange bounded framed data, exercise cancellation and first-instance collision, and force a mismatch between the impersonated current-process SID and the expected SID. Descriptor tests reject execution, Everyone, anonymous, unprotected, and generic-write variants.

Those mechanism tests temporarily treat the current test-process SID as synthetic control policy. They do not create or log on the installed `awg-control`/`awg-exec` accounts and do not prove effective denial for the execution account, a remote host, or an administrator whose SID differs from control. Those are isolated installed-host gates. The service must also prove that the production pipe is created by the configured LocalSystem broker.

## Verification requirements

- the installed control identity can connect, authenticate, and exchange one bounded execute envelope;
- the installed execution identity and an unrelated local identity cannot open the pipe;
- a non-control administrator that can open the pipe is rejected by exact peer-SID authorization;
- a remote client is rejected and no remote fallback endpoint exists;
- broker shutdown cancels a pending accept and leaves no endpoint instance;
- a forced peer-authentication failure processes no envelope bytes, and a forced revert failure terminates the broker.

## References

- Microsoft — Named Pipe Security and Access Rights: https://learn.microsoft.com/windows/win32/ipc/named-pipe-security-and-access-rights
- Microsoft — Named Pipe Open Modes: https://learn.microsoft.com/windows/win32/ipc/named-pipe-open-modes
- Microsoft — `ImpersonateNamedPipeClient`: https://learn.microsoft.com/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- Microsoft — `OpenThreadToken`: https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken
