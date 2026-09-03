# ADR 0018 — Windows Control Client Response Publication

- Status: Accepted
- Date: 2026-09-03
- Scope: Non-privileged local request submission and create-new response publication on Windows

## Context

The authenticated pipe and bounded broker response stream existed without a control-side owner. A private workflow needs one local command that can submit a validated accepted-request record, retain the response bytes for hosted finalization, and fail without leaving a plausible partial result.

The broker wire transaction commits streamed artifact destinations before returning the decoded response to its caller. The caller must still bind that report to the exact accepted request and attempt it submitted. Publishing the artifact transaction directly to its final path would therefore expose data before the last authority-binding check.

Artifact group and file names are report data. Protocol v1 rejects absolute, parent-relative, sensitive, and globbed file paths, but its portable names can still alias on Windows through case folding or reserved device names. The final host destination is control-plane policy and must not be supplied by the request or broker.

## Decision

`awg execute-local` is a Windows-only, non-elevated command with exactly three trusted workflow inputs:

```text
--accepted <bounded canonical accepted-request file>
--attempt <protocol identifier>
--output <create-new absolute final directory>
```

It reads and validates the accepted record without echoing its contents or path, constructs the execute-only envelope, and connects only to the fixed authenticated pipe. One context-aware exchange writes one bounded frame, validates the complete response stream and acknowledgement, closes the connection, and then requires the execution report to bind to the submitted accepted record and exact attempt identifier.

The output parent must already exist beneath control-owned runner storage, must not be a filesystem root, and must contain no reparse directory in its existing path. The selected final directory must not exist. The destination creates a cryptographically unpredictable sibling staging directory and records every directory and file it creates. It does not recursively delete an unenumerated tree.

Artifacts are staged under:

```text
artifacts/<group>/<validated reported path>
```

The destination independently rejects Windows-reserved segments, case-folded group/directory/file aliases, unexpected stream order, duplicate opens, incomplete artifact transactions, and any create collision. Every file uses create-new semantics and is synced before it can be finalized. Request data never selects the parent, final directory, pipe, or metadata names.

The broker stream's artifact commit only marks private staging complete. After stream digests, terminal marker, acknowledgement, EOF, report binding, and attempt binding pass, the client creates and syncs:

```text
execution-report.json
stdout.bin
stderr.bin
```

It then publishes the entire response with one same-parent directory rename. No fallible verification follows a successful rename, so a published attempt cannot be reported as retryable merely because optional status output failed. Before rename, every failure aborts the exact recorded staging objects. A pre-existing or racing final destination is preserved and causes a closed failure.

## Security boundary

This transaction is not a generic safe extractor into an attacker-writable parent. Its unpredictable staging name and reparse/collision checks protect the report namespace, while the future runner installer must make the output parent writable by the control identity and inaccessible to the execution identity. The control identity and trusted workflow select `--output`; requester-controlled issue fields must never be interpolated into that argument as shell source.

The local directory is proposed response evidence, not an authoritative `ResultRecord`. It has no hosted `finalized_at` or finalizer workflow provenance. A later private hosted step must validate the report and artifact digests before publication and create the authoritative result record.

## Alternatives considered

### Publish artifacts as the broker reader commits them

Rejected. Report-to-envelope binding occurs after the reader returns, so an invalidly bound report could leave apparently complete artifacts at the final path.

### Extract beneath a request or artifact-provided destination

Rejected. It would let execution data select host filesystem policy and could collide with control checkout or runner credential paths.

### Overwrite or merge an existing response directory

Rejected. Retry and stale-attempt ambiguity would make it impossible to distinguish one complete exchange from mixed output.

### Return report and artifact bytes only through process stdout

Rejected. Output and artifacts are independently bounded but can be too large for safe shell capture, and partial pipeline writes do not provide create-new transactional publication.

## Consequences and evidence limits

The control exchange is platform-neutral and injected tests exercise canonical envelope transmission, cancellation, connection, rejection, response binding, attempt binding, publication, and abort behavior. Windows tests exercise actual create-new files, same-parent publication, collisions, case aliases, reserved names, cleanup, and a reparse parent; the symlink case may skip where the host lacks symbolic-link privilege.

A native integration test connects through the real authenticated named pipe using the current test identity as synthetic control, runs a fake execution backend through the real broker session, and reads the published report/output directory. It does not use the installed `awg-control` account, GitHub runner, private repository, or installed broker service. It does not prove that the execution identity is denied the future runner/output parent. Those remain isolated installed-host gates.

## References

- [ADR 0010 — Windows Authenticated Named-Pipe IPC](0010-windows-authenticated-named-pipe.md)
- [ADR 0012 — Bounded Local Broker Response Stream](0012-bounded-local-broker-response-stream.md)
- [ADR 0017 — Windows Create-New Installer Transaction](0017-windows-create-new-installer-transaction.md)
