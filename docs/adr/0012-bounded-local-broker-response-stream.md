# ADR 0012: Bounded Local Broker Response Stream

## Status

Accepted.

## Context

The workstation execution report intentionally contains metadata rather than stdout, stderr, or artifact bytes. Retained output can be several MiB per stream and artifact content can total one GiB, so embedding all data in one JSON record would create an avoidable privileged-process allocation and make partial-transfer cleanup ambiguous.

The Windows collector also retains already-authorized file handles opened under execution authority. The broker must stream those handles directly. Reopening a report path later as LocalSystem would turn artifact reporting into a privileged filesystem proxy.

## Decision

Each authenticated broker connection carries exactly one request and one terminal response. A response is either a closed rejection or an execution stream. All records and data chunks use the existing four-byte big-endian frame length. The fixed order is:

```text
response preamble
[canonical execution report]
[retained stdout chunks]
[retained stderr chunks]
[artifact 1 chunks]
...
[artifact N chunks]
connection EOF
```

The preamble is strict JSON, version `1`, and at most 1,024 encoded bytes. An execution preamble uses `outcome = execution`, `failure = none`, and carries SHA-256 values for the exact retained stdout and stderr byte sequences. A rejection uses `outcome = rejected`, has empty digest fields, and selects one coarse failure from this closed set:

```text
invalid_frame
invalid_envelope
authorization_denied
execution_unavailable
response_unavailable
```

Rejections contain no request value, path, script, credential, native error text, or management operation. They have no execution report and cannot claim a hosted authoritative result.

The next execution frame is the canonical validated protocol v1 `ExecutionReport`. Its retained byte counts determine exactly how many stdout and stderr bytes follow. The independent retained digests are necessary because report output SHA-256 values describe each complete observed stream; when output is truncated, that full-stream digest does not by itself authenticate the returned prefix.

Data uses non-empty frames of at most 65,536 bytes. Zero-length output or artifacts consume no data frame. Artifact payloads follow `report.artifacts.files` order and use the manifest's exact size and SHA-256. The writer opens only the exact group/path pair through the lifecycle-owned artifact bundle, streams from that handle, checks EOF and digest, closes each reader, and closes the bundle on every terminal path.

The receiver allocates only the protocol-bounded retained output. It streams artifacts into a response-scoped destination transaction. Relative artifact identities come only from the already validated report. A transaction is committed only after every destination is closed, every declared byte count and digest matches, and EOF proves that no trailing frame exists. Truncation, overrun, digest mismatch, destination error, missing sink, or trailing data aborts the transaction.

The wire package does not choose a filesystem destination or upload service. A later control client owns that policy under the control identity. The broker-side runtime must close the connection after its one response; an incomplete stream is a transport failure, not an authoritative result.

## Consequences

- Artifact content remains bounded in memory and is never reopened under broker authority.
- Receivers can reject corruption and clean partial destinations without trusting frame boundaries alone.
- Retained output is additionally bound even when the full stream was truncated.
- The manifest order is protocol-significant for the local stream.
- There is no resume within a connection. A broken response must be discarded; higher-level retry policy must not silently execute a new attempt under the same terminal identity.
- The contract does not implement authenticated IPC, the broker execution loop, a control-side filesystem sink, GitHub upload, hosted finalization, or service lifecycle. Those remain separate authority boundaries.

