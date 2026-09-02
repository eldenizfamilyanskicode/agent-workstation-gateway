# ADR 0013: Bounded Broker Session Orchestration

## Status

Accepted.

## Context

Authenticated IPC, strict execute envelopes, installation policy, restricted execution, and response streaming are separate defenses. Joining them incorrectly could still create a confused deputy—for example by launching before authorization, using mutable caller configuration, reflecting request data in privileged errors, or letting an authenticated stalled peer monopolize the only pipe forever.

The broker must also distinguish a command that legitimately reports `runtime_failed` from an internal session failure that could not produce a trustworthy bound report.

## Decision

`internal/brokersession` owns exactly one request/response state machine per already-authenticated connection. It is constructed only from:

- a valid installed configuration copied into session-owned slices;
- a copied, preflight-validated safe base environment;
- a required native path resolver;
- the shared execution runner, which itself requires a native launcher;
- one lowercase 40-hex installed gateway source SHA;
- fixed local I/O timing policy.

No one of those values is request-selectable. Default timing is 30 seconds to receive one request, 30 minutes for the complete response write, and 30 seconds for each tiny terminal acknowledgement read. Construction caps those values at five minutes, one hour, and five minutes respectively. These are service policy options, not protocol fields.

The session sequence is closed:

1. read one frame no larger than the execute-envelope limit under the request deadline;
2. strictly decode the execute envelope and accepted-request digest binding;
3. authorize shell, working directory, execution identity, environment, capabilities, and artifacts through existing installed policy;
4. recheck cancellation before starting the shared lifecycle;
5. run exactly once;
6. independently bind the report to the accepted request, attempt ID, and installed source SHA;
7. stream the terminal execution exchange and consume/close its artifact bundle;
8. return so the caller closes the connection.

A malformed frame, invalid envelope, authorization denial, unavailable execution lifecycle, or untrustworthy response maps to the corresponding closed wire failure. Raw request text, path, script, native error, credential, or unknown field name is never copied into the response. A native launch failure that the shared lifecycle can represent remains a valid `runtime_failed` execution report; an internal lifecycle/report-construction failure is a coarse rejection.

Response and acknowledgement I/O uses fresh fixed deadlines rather than the execution context. This allows a timed-out or cancelled command to return its terminal report while keeping cleanup bounded. It does not permit a second request on the connection. Missing or invalid acknowledgement closes the session as a transport failure.

The Windows pipe exposes context-aware overlapped reads/writes to this state machine. Pre-cancelled operations transfer no data; cancellation calls `CancelIoEx`. Compatibility `io.Reader`/`io.Writer` methods remain for bounded codec use with a caller-owned connection lifecycle.

## Consequences

- Authentication remains a prerequisite supplied by native IPC; the session does not infer identity from request fields.
- Authorization always precedes workload execution, and there is no current-user or broker-identity fallback.
- One control peer can still request a long permitted command, but cannot choose the broker I/O deadlines or start a second request on the same pipe.
- Unit tests prove orchestration with fake process internals. The Windows integration test proves current-process peer authentication plus full request/response mechanics, not LocalSystem service startup or installed execution-account isolation.
- Protected-state loading, real Windows dependency composition, service lifecycle, control-side artifact destinations, persistent retry/idempotency state, and private GitHub transport remain separate follow-up boundaries.
