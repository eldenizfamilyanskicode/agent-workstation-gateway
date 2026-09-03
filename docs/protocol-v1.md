# Protocol v1 Contracts

This document defines the implemented Agent Workstation Gateway protocol v1 request, accepted-request ledger, non-authoritative execution report, and authoritative result records.

The public machine-readable contracts are:

- [`request.schema.json`](../protocol/schemas/v1/request.schema.json);
- [`accepted-request.schema.json`](../protocol/schemas/v1/accepted-request.schema.json);
- [`execution-report.schema.json`](../protocol/schemas/v1/execution-report.schema.json);
- [`result.schema.json`](../protocol/schemas/v1/result.schema.json).

The Go implementation is [`protocol/v1`](../protocol/v1). Mutually bound synthetic examples are in [`protocol/examples/v1`](../protocol/examples/v1).

## Security boundary

A request is untrusted data. It can describe work inside authority already configured by the workstation owner, but it cannot grant that authority to itself.

Protocol v1 deliberately has no request fields for:

- an OS identity or run-as user;
- approved development roots;
- environment variables or credentials;
- a GitHub workflow, branch, tag, or source revision;
- runner, broker, service, account, ACL, or capability management;
- Docker or other host-powerful capabilities;
- result-publication credentials;

Unknown fields are rejected. Adding one of these names to an issue body therefore cannot turn it into management authority.

The request contract validates syntax and platform-neutral meaning. It does not authorize the working directory or touch the filesystem. The later broker boundary must canonicalize the path near launch time, prove it is below an administrator-configured approved root, reject link/reparse escape, and launch only as the fixed restricted execution identity.

## Encoding and envelope limits

Each record is exactly one UTF-8 JSON object. Encoded limits are 65,536 bytes for a request, 131,072 bytes for an accepted-request record, and 262,144 bytes each for an execution report or result record.

- A UTF-8 byte-order mark is not accepted as JSON syntax.
- Invalid UTF-8 is rejected rather than replaced.
- Every declared field is required. This includes an empty `process_id` for foreground execution, explicit `null` for an unavailable exit code, and empty artifact arrays.
- Unknown fields, duplicate object keys at any depth, trailing JSON values, and malformed JSON are rejected.
- No implicit defaults are applied during decoding or canonicalization.

The JSON Schema provides a portable structural preflight. The Go implementation owns the complete semantic and UTF-8 byte-limit validation. Custom `x-awg-max-utf8-bytes` schema annotations expose byte limits where JSON Schema's standard `maxLength` counts characters instead.

## Request fields

| Field | Type | Contract |
|---|---|---|
| `protocol_version` | integer | Exactly `1`. |
| `request_id` | string | 1–64 ASCII bytes; lowercase letters, digits, `.`, `_`, and `-`; starts with a letter or digit. Stable idempotency identity. |
| `session_id` | string | Same syntax as `request_id`. Groups related requests without granting global ordering or authority. |
| `actor` | string | Same syntax as `request_id`. Descriptive requester identity; transport provenance remains authoritative. |
| `operation` | string enum | `execute`, `start`, `status`, `stop`, or `logs`. These are execution-identity workload operations, never gateway administration. |
| `process_id` | string | Empty for `execute`; otherwise a 1–64 byte identifier scoped by `session_id`. |
| `shell` | string enum | One of `bash`, `cmd`, `git-bash`, `powershell`, or `pwsh`. The installed platform policy still decides whether that shell is available. |
| `working_directory` | string | Canonical absolute Windows drive path or canonical absolute POSIX path; at most 1,024 UTF-8 bytes. This is a requested location, not authorization. |
| `script` | string | Non-whitespace inline script, 1–49,152 UTF-8 bytes, with no NUL. It remains data until the restricted execution launch. |
| `timeout_seconds` | integer | 1–86,400 inclusive. |
| `max_output_bytes` | integer | 1,024–5,242,880 inclusive; the retained-prefix limit for each output stream. |
| `artifacts` | array | Zero to eight artifact-selection groups. Must be `[]`, not `null`, when unused. |

All identifiers are case-sensitive. Protocol validation does not infer actor authority from the `actor` string; the private control transport binds the accepted request to sender metadata from the immutable opened-event snapshot.

`start` launches the supplied script under the same fixed identity, sanitized environment, approved working directory, and native process-tree boundary as `execute`; `timeout_seconds` is its maximum lifetime. `status` returns state metadata, `logs` returns bounded retained output plus metadata, and `stop` synchronously reaps the owned tree. Those three lifecycle requests use the exact placeholder `"-"` in `script`, require no artifacts, and can address only the same `session_id`/`process_id` and original working directory. Broker restart or uninstall reaps all registered trees.

## Working-directory syntax

Windows requests use a drive-rooted path with backslash separators, for example:

```text
C:\Users\Alice\Projects\demo
```

POSIX requests use a slash-rooted path, for example:

```text
/home/alice/projects/demo
```

The protocol rejects:

- relative paths;
- UNC paths in v0.1;
- mixed Windows/POSIX separators;
- empty, `.` or `..` path segments;
- duplicate or trailing separators except the filesystem root itself;
- control characters and NUL;
- ambiguous Windows trailing dots/spaces, invalid Windows filename characters, and reserved device names.

These rules remove avoidable aliases before digesting. They do not replace native path resolution, root ancestry checks, ACL/ownership enforcement, or link/reparse protections at execution time.

## Artifact selections

Each selection has a unique lowercase identifier in `name` and one to sixteen relative slash-separated patterns in `paths`.

```json
{
  "name": "test-results",
  "paths": ["test-results/**/*.png"]
}
```

Limits and safety rules:

- at most eight groups and 64 paths across the whole request;
- group names are at most 32 ASCII bytes;
- each path is at most 256 UTF-8 bytes;
- absolute paths, drive prefixes, backslashes, NUL, empty segments, `.` and `..` are rejected;
- malformed glob syntax is rejected;
- duplicate groups and duplicate paths inside one group are rejected;
- `.git`, `.ssh`, `.gnupg`, `.aws`, `.azure`, `.kube`, `.runtime`, `.env`, and `.env.*` path segments are rejected.

Artifact selection is not a filesystem read capability by itself. The later collector must enumerate/read under restricted execution authority, remain inside the validated working root, reject links/reparse escapes, and enforce file count and byte limits.

Portable matching is case-sensitive and segment-based. `*`, `?`, and character classes do not cross `/`; a segment exactly equal to `**` matches zero or more complete segments. Native collectors do not delegate matching to a platform shell.

The implemented execution lifecycle couples every reported file to a closeable content bundle. Each reported path must match an accepted pattern in the same group, and each omission must cite an exact accepted pattern. On Windows, the collector hashes and later streams through the same retained no-share-write/delete handle opened under execution authority. Manifest-only reopening under broker authority is forbidden. Hosted artifact upload remains a separate later boundary.

## Local broker response stream

The internal workstation handoff is a single terminal stream, not another authoritative ledger format. Its strict preamble schema and synthetic example are under [`runtime`](../runtime). An execution response contains, in order:

1. a preamble with version, execution outcome, and SHA-256 for the exact retained stdout/stderr prefixes;
2. the canonical validated `ExecutionReport`;
3. retained stdout frames totaling `report.stdout.retained_bytes`;
4. retained stderr frames totaling `report.stderr.retained_bytes`;
5. each artifact's bytes in manifest order, totaling its declared size;
6. a fixed terminal marker, followed by a fixed client acknowledgement and server close;
7. connection EOF observed by the client.

Every data frame is non-empty and at most 65,536 bytes. Zero-byte logical content has no frame. The receiver verifies exact lengths, retained-output hashes, artifact hashes, the `AWG\x01DONE`/`AWG\x01ACK` completion exchange, and final EOF. Artifact destinations are one response-scoped transaction: partial files abort after any framing, digest, destination, marker, acknowledgement, or close failure and commit only after the whole stream is valid. The completion exchange is necessary because immediate Windows message-pipe disconnect can otherwise discard a response tail that the client has not consumed.

On Windows, `awg execute-local` supplies the implemented control-side owner of that transaction. Artifact commit makes only an unpredictable create-owned staging tree complete. The client next validates the report against the exact accepted request and attempt, writes canonical report plus retained stdout/stderr metadata files, and exposes the whole response with one same-parent rename into a caller-selected create-new directory. Portable names are additionally rejected when they are Windows-reserved or case-fold to an alias. See [ADR 0018](adr/0018-windows-control-client-response-publication.md).

A rejection has only the preamble's coarse closed failure code followed by the same completion acknowledgement and EOF; it has no report or requester-controlled diagnostic. Neither response form can add `finalized_at` or workflow provenance; only the separate trusted hosted finalizer can create an authoritative `ResultRecord`. See [ADR 0012](adr/0012-bounded-local-broker-response-stream.md).

The broker session reads exactly one execute envelope under fixed local I/O deadlines, authorizes before calling the execution lifecycle, binds the returned report again, and then performs exactly one terminal exchange. Those deadlines and coarse failure mappings are installed implementation policy, never request fields. See [ADR 0013](adr/0013-bounded-broker-session-orchestration.md).

## Canonical request and digest

After strict decoding and semantic validation, AWG encodes the typed request in the fixed field order owned by the Go contract with no insignificant whitespace. It then computes SHA-256 over those canonical bytes and represents the digest as 64 lowercase hexadecimal characters.

Consequences:

- JSON whitespace and object-property order do not change the digest;
- equivalent JSON string escapes decode to the same string and canonical bytes;
- array order and string contents remain significant;
- no field is dropped or defaulted;
- a canonical form larger than 65,536 bytes is rejected even when a request was constructed programmatically instead of decoded from transport bytes.

The canonical request bytes and digest bind the accepted ledger record. They do not authenticate the requester by themselves; transport provenance and create-once ledger semantics provide that control-plane context.

## Accepted-request ledger record

The authoritative accepted request is created at this fixed private-control ledger path before workstation execution starts:

```text
ledger/requests/<request-id>/accepted.json
```

The issue body is only a submission envelope. A disposable hosted accept job reads the immutable `issues: opened` event snapshot, performs strict request validation, computes the canonical request digest, and uses control-owned compare-and-create authority to write `accepted.json`. It must not refetch a later edited issue body.

The accepted record contains:

| Field | Contract |
|---|---|
| `protocol_version` | Exactly `1`. |
| `request_id` | Must equal the embedded request ID. |
| `request_digest` | SHA-256 of the canonical embedded request; must recompute exactly. |
| `request` | The complete strictly validated protocol v1 request. |
| `issue` | Positive issue number, bounded node identity, and sender numeric ID/login from the opened-event snapshot. |
| `workflow` | Private repository, run ID/attempt, exact `issues`/`opened` event, and lowercase 40-hex workflow source SHA. |
| `control_source_sha` | Lowercase 40-hex source revision of the fixed control implementation selected by the installation. |
| `accepted_at` | Canonical RFC 3339 UTC timestamp using `Z`. |

Repository and login strings are descriptive provenance, not authorization fields supplied by the request. The hosted accept job derives them from trusted event context. The Go validator binds request ID and digest, but repository visibility and installation identity remain control-workflow policy checks.

Compare-and-create behavior is part of the transport contract:

- an unseen request ID can create one accepted record;
- the same ID and digest is a duplicate or recovery observation, not a new execution grant;
- the same ID with a different digest is a conflict and fails closed;
- the accepted record is never rewritten to represent retries.

## Non-authoritative execution report

The workstation produces an `ExecutionReport` containing the accepted request ID/digest, stable attempt ID, installed gateway source SHA, command status, timing, full-stream output metadata, and independent artifact manifest. Its strict field set has no `finalized_at` or `workflow`: requester/workload/workstation data cannot claim that hosted finalization happened or choose its publication provenance.

The report binds to `accepted.json` before finalization. The binding requires identical request ID/digest, retained stdout/stderr prefixes within the accepted per-stream limit, and artifact groups/status consistent with the accepted selections. The report is proposed terminal evidence, not the durable authoritative ledger record.

`FinalizeResultRecord` is the typed hosted boundary. It accepts a valid accepted record and bound execution report, then requires the finalizer to supply a canonical UTC finalization timestamp and workflow provenance matching the acceptance run (a later rerun attempt is allowed). Only the resulting `ResultRecord` is eligible for create-once publication.

## Authoritative result record

The terminal result has one fixed private-control ledger path:

```text
ledger/requests/<request-id>/result.json
```

A result record contains the accepted request ID/digest, a stable execution attempt ID, the installed gateway source SHA observed at execution, command outcome, timing, bounded output metadata, an independent artifact outcome, hosted finalization time, and workflow provenance.

Standalone result validation proves the record's shape and internal invariants. Before publication, the finalizer must also validate it against `accepted.json`. The implemented binding check requires:

- identical request ID and canonical request digest;
- stdout and stderr retained prefixes no larger than the request's accepted per-stream output limit;
- `not_requested` artifacts exactly when the accepted request has no artifact groups;
- every returned file or omission to name an accepted artifact group;
- the same private repository, workflow run ID, event, and workflow source SHA as acceptance.

A rerun may have a later workflow `run_attempt`; it does not acquire permission to change the accepted request or execution attempt.

### Command states and exit codes

Command outcome is a closed state independent of artifact collection:

| `command_status` | `exit_code` | Meaning |
|---|---|---|
| `completed` | exactly `0` | The launched command completed successfully. |
| `failed` | integer `1`–`4294967295` | The command completed with a platform exit code. |
| `timed_out` | `null` | The configured timeout terminated the attempt; no ordinary exit code is claimed. |
| `cancelled` | `null` | Trusted control cancelled the attempt. |
| `runtime_failed` | `null` | The gateway could not obtain an ordinary command completion, such as a launch or boundary failure. |

`started_at`, `finished_at`, and `finalized_at` are canonical RFC 3339 UTC timestamps using `Z`. Finish cannot precede start, finalization cannot precede finish, and `duration_ms` equals the elapsed duration truncated to whole milliseconds.

### Output metadata

`stdout` and `stderr` each contain:

| Field | Contract |
|---|---|
| `sha256` | 64 lowercase hex characters for the complete observed stream. |
| `total_bytes` | Complete observed byte count. It can exceed the retained-prefix limit. |
| `retained_bytes` | Prefix bytes retained for return; never greater than `total_bytes` or the accepted request limit. |
| `truncated` | `true` exactly when some observed bytes were not retained. |

The ledger record does not embed output bytes. The execution/finalization handoff may carry bounded retained bytes as data, while the metadata keeps truncation explicit. A false `truncated` flag requires all observed bytes to have been retained.

### Artifact manifest

Artifact collection has its own status so a successful command cannot hide an artifact failure:

| `artifacts.status` | Required shape |
|---|---|
| `not_requested` | Both arrays empty; valid only when the accepted request has no artifact selections. |
| `complete` | At least one file and no omissions. |
| `complete_with_omissions` | One or more explicit omissions; files may also be present. |
| `failed` | One or more explicit omissions; any successfully collected files remain visible. |

Each file records its accepted group, slash-separated relative path, SHA-256, and byte size. Actual file paths cannot contain glob metacharacters. Each omission records its group, original relative pattern, and one closed reason:

```text
byte_limit
collection_failed
file_limit
link_rejected
no_match
policy_rejected
read_failed
unsupported_type
```

The manifest permits at most 256 file records and 128 omissions. File paths are at most 1,024 UTF-8 bytes, individual files at most 536,870,912 bytes, and the manifest's summed file sizes at most 1,073,741,824 bytes. Paths remain relative, reject traversal, control characters, links reported by collection policy, and known sensitive segments. Duplicate group/path files and duplicate group/pattern/reason omissions are rejected.

These metadata limits do not authorize a filesystem read. The restricted collector must still enforce the accepted glob, approved root, native link/reparse checks, OS permissions, and byte/count limits while accessing files.

## Finalization and recovery semantics

Workstation output is a proposed result, not the authoritative ledger. Only the disposable hosted finalizer has result-publication authority. It validates the proposed record against the create-once accepted record and creates `result.json` without overwrite.

Therefore:

- command success plus artifact failure is represented as `command_status: completed` with `artifacts.status: failed`;
- command failure plus successfully collected diagnostics keeps the command failure and independent artifact success;
- a finalization failure is the absence of a new authoritative `result.json`, never an authoritative successful result with a misleading status;
- recovery may re-finalize the same accepted digest and terminal attempt without re-executing it;
- a different terminal result for an already finalized request is a create-once conflict and fails closed.

Actions logs and transient cross-job artifacts are supporting transport evidence, not replacements for the durable private ledger.

## Canonical ledger encoding

Accepted records, execution reports, and result records use the same typed fixed-order JSON canonicalization as requests: no insignificant whitespace, no dropped/defaulted fields, and SHA-256 over the resulting bytes when a record digest is needed. Canonical encoding revalidates semantics and enforces the record-specific encoded limit even for programmatically constructed values.

The canonical request digest inside `accepted.json`, an execution report, and `result.json` always identifies the request bytes, not the formatting of another record. `DigestAcceptedRequestRecord`, `DigestExecutionReport`, and `DigestResultRecord` are available for audit/integrity uses but do not replace control-owned compare-and-create publication.

## Versioning and compatibility

Protocol v1 is a closed contract. A decoder for v1 accepts only `protocol_version: 1` and the exact field sets above.

An incompatible field, meaning, enum, or validation change requires a new protocol version. Compatible implementation fixes may make validation more faithful to this documented contract, but must not silently reinterpret already accepted canonical bytes.

Non-Go implementations may use the JSON Schema for structural validation, but they must also reproduce the semantic rules, raw/canonical byte limits, duplicate-key rejection, canonical field order, and digest algorithm. Passing the schema alone is not sufficient evidence of protocol compatibility.

## Error disclosure

The Go codecs return structured error kind, field, and rule identifiers. They do not include raw values or unknown key names in error text. Control-plane logging may record bounded provenance and these rule identifiers, but must not echo a secret merely because it appeared in an invalid record.
