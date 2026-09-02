# ADR 0011 — Windows Artifacts Under Execution Authority

- Status: Accepted
- Date: 2026-09-03
- Scope: Post-command artifact selection, hashing, and content lifetime on Windows

## Context

Artifact patterns are workload-controlled read requests. If a LocalSystem broker expands those patterns with its own filesystem authority, the artifact feature becomes a generic privileged file reader even when paths look lexically relative. Returning only hashes in an execution report is also insufficient: the later control response needs stable bytes whose content still corresponds to the reported digest.

Artifact collection begins only after the owned workload process tree has been reaped. The accepted request already bounds group names and slash-relative patterns, but the native collector must independently bind those patterns to installed execution identity, the authorized working directory, and real filesystem objects.

## Decision

The shared execution lifecycle returns an `ArtifactBundle` alongside the report. A manifest containing files is accepted only with a bundle, every file must match at least one accepted pattern in its group, and every omission must name an exact accepted pattern. Invalid, failed, or unbound collections are closed before the lifecycle substitutes an explicit `collection_failed` manifest.

Glob matching is portable and case-sensitive. `/` separates path segments; `*`, `?`, and character classes operate within one segment; a segment exactly equal to `**` matches zero or more complete segments. This definition does not inherit Windows' case-folding or shell-specific glob behavior.

The Windows collector is constructed from validated installed configuration plus the fixed execution-token source. It accepts only the exact installed execution user/primary-group pair, an installed approved root, a canonical working directory beneath that root, and protocol-valid relative selections.

For every collection it:

1. acquires the configured execution token and independently verifies TokenUser and TokenPrimaryGroup;
2. duplicates an impersonation token, pins the goroutine to its OS thread, and applies that token before any root/working-directory open, enumeration, candidate open, or content read;
3. opens approved-root and working-directory guards with `FILE_FLAG_OPEN_REPARSE_POINT`, rejects reparse/non-directory handles, resolves their final DOS paths, requires exact configured paths, and keeps the guards open;
4. walks deterministically without traversing reparse or sensitive directories;
5. opens each matched candidate with `GENERIC_READ`, `FILE_FLAG_OPEN_REPARSE_POINT`, and only `FILE_SHARE_READ`;
6. requires a regular disk file, no reparse attribute, exactly one hard link, an exact final path, and containment beneath both verified working directory and approved root;
7. checks file and remaining aggregate size before hashing, streams SHA-256, rewinds the same stable handle, and retains it in the bundle;
8. reverts thread impersonation before returning. A failed revert terminates the broker process.

Only read sharing is granted while a collected handle remains owned by the bundle. Windows therefore rejects a conflicting write, rename, or delete open until the content is streamed or the bundle closes. `Open(group, path)` transfers one one-shot reader for an exact manifest entry; unknown, duplicate, or post-close opens fail. Bundle close releases every reader/handle and is idempotent.

The fixed limits are:

| Boundary | Limit |
|---|---:|
| accepted selection groups / patterns | protocol v1: 8 groups, 16 per group, 64 total |
| scanned filesystem entries | 8,192 |
| relative traversal depth | 32 segments |
| published files | protocol v1: 256 |
| one file | protocol v1: 512 MiB |
| all published file entries | protocol v1: 1 GiB |

The collector never reads a file that already exceeds its per-file or remaining-total byte allowance. One deterministic omission per accepted pattern records `no_match`, `link_rejected`, `policy_rejected`, `unsupported_type`, `read_failed`, `file_limit`, `byte_limit`, or `collection_failed`. `.git`, `.ssh`, `.gnupg`, `.aws`, `.azure`, `.kube`, `.runtime`, `.env`, and `.env.*` segments are never traversed or published.

## Alternatives considered

### Expand and read patterns as LocalSystem

Rejected. Lexical containment would not prevent a reparse, hard-link, or race from converting artifact selection into privileged file disclosure.

### Return a manifest and reopen files later

Rejected. Reopening after reversion would use broker authority and would not bind streamed bytes to the hash/size observed during collection.

### Copy every artifact into broker state

Rejected for v0.1. It adds privileged storage, cleanup, quota, confidentiality, and disk-space failure modes. Stable one-shot handles preserve the authority decision and avoid a second copy.

### Follow hard links when the visible path is inside the root

Rejected. A hard link can name the same file through another directory, while final pathname APIs do not provide a reliable original-parent boundary. Requiring link count one is deliberately conservative.

## Consequences and evidence limits

Ordinary Windows tests use the current process token as a synthetic execution token. They exercise real impersonation calls, recursive matching, stable content/hash metadata, write/delete sharing denial while a bundle is live, sensitive-directory exclusion, hard-link rejection, sparse oversize rejection before content reads, file/depth limits, cancellation, and token-identity mismatch. The local symlink test may skip when the host lacks symbolic-link privilege; hosted/isolated evidence must state whether it actually ran.

These tests do not prove that installed `awg-exec` can read allowed artifacts or that it is denied gateway, runner, human, or unrelated files. They also do not implement broker wire streaming or GitHub upload. Those remain integration and isolated-host gates.

## Verification requirements

- an installed execution token collects expected files and cannot collect a synthetic forbidden human/control file;
- a reparse directory and file, junction, hard link, alias, and path replacement do not escape the authorized working directory;
- manifest bytes and streamed bytes have the same length and SHA-256 while concurrent replacement remains denied;
- byte, file, entry, depth, cancellation, and collection-time limits bound actual work;
- broker response interruption closes every retained handle and leaves no privileged spool;
- private control upload verifies the received digest before publication.

## References

- Microsoft — `CreateFile` sharing and reparse behavior: https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilew
- Microsoft — `GetFinalPathNameByHandle`: https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew
- Microsoft — `BY_HANDLE_FILE_INFORMATION`: https://learn.microsoft.com/windows/win32/api/fileapi/ns-fileapi-by_handle_file_information
- Microsoft — `SetThreadToken`: https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadtoken
- Microsoft — `RevertToSelf`: https://learn.microsoft.com/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself
