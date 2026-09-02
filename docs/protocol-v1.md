# Protocol v1 Request Contract

This document defines the implemented request side of Agent Workstation Gateway protocol v1. The result, accepted-ledger, attempt, and finalization records are not yet defined at this checkpoint.

The public machine-readable contract is [`protocol/schemas/v1/request.schema.json`](../protocol/schemas/v1/request.schema.json). The Go implementation is [`protocol/v1`](../protocol/v1), and a synthetic request is available at [`protocol/examples/v1/request.json`](../protocol/examples/v1/request.json).

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
- persistent-process lifecycle operations.

Unknown fields are rejected. Adding one of these names to an issue body therefore cannot turn it into management authority.

The request contract validates syntax and platform-neutral meaning. It does not authorize the working directory or touch the filesystem. The later broker boundary must canonicalize the path near launch time, prove it is below an administrator-configured approved root, reject link/reparse escape, and launch only as the fixed restricted execution identity.

## Encoding and envelope limits

The accepted request is exactly one UTF-8 JSON object.

- Maximum encoded request size: 65,536 bytes.
- A UTF-8 byte-order mark is not accepted as JSON syntax.
- Invalid UTF-8 is rejected rather than replaced.
- Every field is required, including an empty `artifacts` array when no artifacts are requested.
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
| `shell` | string enum | One of `bash`, `cmd`, `git-bash`, `powershell`, or `pwsh`. The installed platform policy still decides whether that shell is available. |
| `working_directory` | string | Canonical absolute Windows drive path or canonical absolute POSIX path; at most 1,024 UTF-8 bytes. This is a requested location, not authorization. |
| `script` | string | Non-whitespace inline script, 1–49,152 UTF-8 bytes, with no NUL. It remains data until the restricted execution launch. |
| `timeout_seconds` | integer | 1–86,400 inclusive. |
| `max_output_bytes` | integer | 1,024–5,242,880 inclusive, per the later output-capture contract. |
| `artifacts` | array | Zero to eight artifact-selection groups. Must be `[]`, not `null`, when unused. |

All identifiers are case-sensitive. Protocol validation does not infer actor authority from the `actor` string; the private control transport binds the accepted request to sender metadata from the immutable opened-event snapshot.

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

## Canonical request and digest

After strict decoding and semantic validation, AWG encodes the typed request in the fixed field order owned by the Go contract with no insignificant whitespace. It then computes SHA-256 over those canonical bytes and represents the digest as 64 lowercase hexadecimal characters.

Consequences:

- JSON whitespace and object-property order do not change the digest;
- equivalent JSON string escapes decode to the same string and canonical bytes;
- array order and string contents remain significant;
- no field is dropped or defaulted;
- a canonical form larger than 65,536 bytes is rejected even when a request was constructed programmatically instead of decoded from transport bytes.

The canonical request bytes and digest bind the accepted ledger record. They do not authenticate the requester by themselves; transport provenance and create-once ledger semantics provide that control-plane context.

## Versioning and compatibility

Protocol v1 is a closed contract. A decoder for v1 accepts only `protocol_version: 1` and the exact field set above.

An incompatible field, meaning, enum, or validation change requires a new protocol version. Compatible implementation fixes may make validation more faithful to this documented contract, but must not silently reinterpret already accepted canonical bytes.

Non-Go implementations may use the JSON Schema for structural validation, but they must also reproduce the semantic rules, raw/canonical byte limits, duplicate-key rejection, canonical field order, and digest algorithm. Passing the schema alone is not sufficient evidence of protocol compatibility.

## Error disclosure

The Go codec returns structured error kind, field, and rule identifiers. It does not include raw request values or unknown key names in error text. Control-plane logging may record bounded provenance and these rule identifiers, but must not echo a secret merely because it appeared in an invalid request.
