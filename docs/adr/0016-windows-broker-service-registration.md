# ADR 0016: Windows Broker Service Registration

## Status

Accepted.

## Context

The LocalSystem broker lifecycle from ADR 0015 needs one installed SCM object. Registration is an elevated management operation, not part of the normal broker protocol, and must not become a generic service manager or let install/request data select privileged service behavior.

A partial installation also needs precise ownership. Rejecting a pre-existing name is safer than adopting, repairing, or deleting a service that the active transaction did not create. The default Windows service descriptor is broader than AWG's management boundary, so a newly created service must remain unable to start while its exact descriptor and recovery policy are converged.

## Decision

`internal/platform/windows/serviceinstall` exposes registration by canonical installation root only. Trusted code fixes:

- service name `AgentWorkstationGatewayBroker`;
- own-process LocalSystem account, normal error control, no dependencies, no service SID, and final automatic start;
- executable `<installation-root>\bin\awg-broker.exe` with exactly `--installation-root <installation-root>`;
- two restart actions after 5 and 30 seconds, followed by no action, with a 24-hour reset period and non-crash failures enabled;
- empty recovery command and reboot message;
- protected service descriptor `O:SYG:SYD:P(A;;0xF01FF;;;SY)(A;;0xF01FF;;;BA)`.

The descriptor requires LocalSystem owner and primary group, a protected DACL, and exactly one non-inheritable full-service-access allow ACE for LocalSystem and Builtin Administrators. Control, execution, Users, Authenticated Users, Everyone, Anonymous, and every other principal receive no service-object ACE. The install specification and normal request protocol contain no service-policy fields.

Before opening a mutating SCM handle, registration validates the canonical root. It then requests only `SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE`, validates the fixed broker image through the exact protected executable boundary, and opens a possible pre-existing service with only `SERVICE_QUERY_STATUS`. Any pre-existing object or ambiguous query failure stops registration without adoption.

A new service is created disabled with the fixed image, arguments, LocalSystem account, and dependencies. Its exact protected descriptor is applied first. Recovery actions, empty command/reboot settings, and non-crash behavior follow. Automatic start and the final description are applied last. The installer then independently queries and compares the complete service configuration, recovery actions/reset/flag/command/reboot settings, and owner/group/DACL.

The returned lease owns rollback only when the native create call positively reports that this transaction created the service. Failure after that point deletes and closes only that owned handle. Commit preserves the verified service and releases the handle. Manager-close failure before commit also rolls the service back; rollback failure takes precedence in the coarse result.

`ProbeFixedService` is a separate read-only diagnostic. It opens the local SCM with `SC_MANAGER_CONNECT` and the one fixed service with `SERVICE_QUERY_STATUS`. No exported API accepts a service name, executable, account, descriptor, recovery command, delete target, or start/stop operation.

## Consequences

- Install/request data cannot redirect LocalSystem service execution or widen service-control authority.
- The service is disabled while its default descriptor is replaced and cannot become automatic until every narrower policy mutation succeeds.
- A colliding or inaccessible pre-existing service is preserved and fails installation closed.
- Rollback is create-owned rather than name-owned; this unit does not define repair, update, uninstall, or arbitrary deletion.
- The 256 MiB protected-executable ceiling is distinct from the unchanged 1 MiB protected-state ceiling.
- Policy, drift rejection, exact synthetic descriptors, transaction failures, rollback, commit, and manager cleanup are unit/injected tested. Ordinary Windows testing also performs only the fixed read-only SCM probe.
- This evidence does not prove elevated service creation, effective descriptor assignment, recovery behavior, LocalSystem startup, or cross-identity service denial. Those remain isolated Windows smoke requirements.
