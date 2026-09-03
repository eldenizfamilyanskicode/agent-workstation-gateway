# ADR 0020 — Bounded Background Process Lifecycle

- Status: Accepted
- Date: 2026-09-03
- Scope: Explicit persistent workload processes for protocol v1

## Context

Development servers sometimes must outlive the request that starts them. Ordinary AWG execution intentionally reaps the complete native process tree, so shell detachment is not an allowed persistence mechanism. Persistence needs an explicit operation that retains the same execution identity, environment, path, and tree ownership.

## Decision

Protocol v1 requests carry a required `operation` and `process_id`. `execute` requires an empty process ID. `start`, `status`, `logs`, and `stop` require a bounded identifier scoped by `session_id`; non-start lifecycle requests carry the exact inert script placeholder `-`. Background operations cannot request artifacts.

`start` uses the same installed authorization, fixed execution identity, sanitized environment, shell invocation, approved working directory, token validation, and native process-tree launcher as foreground execution. The accepted timeout is the maximum process lifetime. A broker-owned in-memory registry retains at most 32 entries and never persists credentials, scripts, or environment values.

`status` returns only bounded state/output metadata. `logs` additionally returns the retained stdout/stderr prefixes. `stop` synchronously terminates and reaps the registered tree before removing its key. Lookup requires the same session, process identifier, and canonical working directory. Duplicate live keys and cross-session/path lookups fail closed.

Natural exit reaps descendants through the native launcher. Lifetime expiry terminates the tree and records `timed_out`. Broker shutdown closes every registered process through the launcher; on Windows, kill-on-close Job Objects remain a final process-exit backstop. Background operation results use the existing bound execution report. A single JSON metadata line precedes any retained stdout in the `logs` response; the durable result contains hashes and sizes, while response files carry the bounded bytes.

## Consequences

Background processes are intentionally not durable across broker/service restart, and their maximum v0.1 lifetime is 24 hours. Logs are memory-bounded and disappear after stop or restart. A long-running script must keep its top-level process alive; spawning a child and exiting still causes the owned tree to be reaped.

This is workload lifecycle authority, not gateway management authority. Requests still cannot select an identity, credential, executable outside installed shell policy, service, ACL, runner, or capability.

## Verification requirements

- shared unit tests for start/status/logs/stop, duplicate and ownership denial, timeout, output bounds, and broker shutdown cleanup;
- Windows exact-commit smoke proving the process survives its start request, returns logs, and is absent after stop;
- Windows timeout/tree-cleanup and uninstall cleanup evidence;
- equivalent native Linux process-group evidence before v0.1 release.
