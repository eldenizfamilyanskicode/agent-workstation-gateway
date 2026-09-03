# ADR 0015: Windows SCM Broker Service Lifecycle

## Status

Accepted.

## Context

The Windows broker composition must run as a long-lived LocalSystem service without turning developer convenience into a current-user or interactive privileged execution path. Service stop and machine shutdown must interrupt both a pending named-pipe accept and an already accepted session; otherwise SCM shutdown could abandon execution or wait for the normal response deadline.

An invalid peer or malformed one-connection exchange must not permanently disable the service. Conversely, retrying every native failure could create an unbounded tight loop or leak a connection handle. The retry boundary must therefore be explicit and closed.

## Decision

The Windows service name is fixed in trusted code as `AgentWorkstationGatewayBroker`. `cmd/awg-broker` is service-only: it accepts exactly `--installation-root <canonical-root>` from the administrator-protected SCM image command line and exposes no console, alternate endpoint, credential-path, or source-ref mode. The installed gateway source SHA is a lowercase 40-hex value embedded by the trusted build through the unexported `main.gatewaySourceSHA` linker variable. An unconfigured or invalid SHA fails before protected state or IPC startup.

`internal/platform/windows/brokerservice` first validates the installation root and source SHA, requires an actual SCM-launched process, and queries the native process TokenUser. It requires the exact LocalSystem SID (`S-1-5-18`); administrator membership or an elevated interactive token is not a substitute. Only then does it dispatch the fixed service handler and construct `brokerhost.Runtime`.

The handler reports:

1. `StartPending` with a checkpoint and wait hint;
2. `Running`, accepting only Stop and Shutdown;
3. `StopPending` with a checkpoint and wait hint after either accepted stop control;
4. a clean service exit only after the owned broker loop returns.

Extra service-start arguments are rejected. Interrogate returns the current Running status; unsupported controls do not change state or expand accepted controls.

The service processes one authenticated connection at a time. A completed session/response error, an invalid authentication preface, or an exact peer-SID mismatch is confined to that closed connection and permits the next accept. Listener creation/accept infrastructure failures, unknown errors, and connection-close failures are terminal. This allowlist is implemented by `brokerhost`, which owns the concrete error types.

`brokerhost.Runtime.Close` atomically prevents later accepts, closes the named-pipe listener, and closes any active accepted connection. Closing the active transport interrupts request/response I/O as well as cancellation of the execution context. The SCM handler waits for the broker-loop goroutine after closing those resources and does not report a clean stop while owned work remains.

The base service is cgo-free and has no event-log, repository, updater, account-management, ACL-management, or shell-management API. Service creation, binary path ACLs, recovery settings, installation rollback, and deletion remain the elevated installer boundary.

## Consequences

- Running `awg-broker` from an interactive shell fails closed even when that shell is elevated.
- Normal request data cannot choose the service name, installation root, source SHA, IPC endpoint, identity, or credential path.
- Bad peers cannot execute and do not permanently stop the listener; native infrastructure corruption does stop it instead of spinning.
- Stop and shutdown own listener, active transport, execution cancellation, and goroutine completion in a deterministic order.
- Unit tests exercise all state/control, retry, and cleanup branches. Native ordinary-host tests exercise SCM-context rejection and actual TokenUser querying.
- This evidence does not prove SCM registration ACLs, recovery policy, a successful installed LocalSystem start, protected-state access under LocalSystem, successful execution-account logon, or effective cross-identity filesystem denials. Those require the mutating installer and isolated Windows smoke system.
