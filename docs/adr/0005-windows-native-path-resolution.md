# ADR 0005 — Windows Native Path Resolution

- Status: Accepted
- Date: 2026-09-03
- Scope: Windows approved-root and working-directory resolution before restricted execution

## Context

Protocol path syntax and segment-aware string comparison remove obvious aliases, but they cannot authorize a live Windows filesystem path. NTFS junctions, symbolic links, mount points, and path replacement can make a lexically contained path resolve somewhere else.

The shared execution policy therefore requires a native resolver. AWG also needs maintained Windows API definitions for later token, Job Object, service, ACL, and named-pipe work while keeping release binaries cgo-free.

## Decision

Windows-native code uses the narrowly scoped, Go-project-maintained `golang.org/x/sys/windows` module. The initial reviewed version is `v0.47.0`. This does not introduce cgo or a runtime DLL dependency; it supplies typed declarations and syscall wrappers over Windows APIs already provided by the operating system.

The Windows resolver opens directory handles with `CreateFileW` and `FILE_FLAG_BACKUP_SEMANTICS`, then obtains normalized DOS final paths with `GetFinalPathNameByHandleW`. Authorization uses those handle-derived final paths, not `filepath.Abs`, string cleaning, or a lexical prefix alone.

For v0.1:

- every configured approved root must exist, be a directory, and resolve natively to the same configured canonical path;
- an approved root that is itself a junction, symbolic link, mount alias, or other final-path alias is rejected;
- the requested working directory must exist and be a directory;
- its native final path must be equal to or segment-contained by one configured root;
- a link or reparse point that resolves outside all configured roots is rejected;
- returned errors identify only a closed failure class and never echo the supplied path.

A link that resolves to another location inside the same approved root is not an authority expansion and may be accepted by this resolver. Native artifact enumeration will still need per-entry handle/link policy because artifact selection is a read/exfiltration boundary.

## Residual race and enforcement boundary

One successful resolution does not freeze a pathname. Another process using the execution identity may rename or replace a writable directory after the resolver closes its handle and before `CreateProcessAsUserW` consumes the current-directory string.

Therefore this resolver is one defense, not a filesystem sandbox:

- the Windows launcher must repeat native resolution as close as possible to process creation;
- administrator-owned configuration and shell paths remain protected from both non-admin identities;
- Windows ACLs must deny the execution identity access to unrelated credentials and data even if a path race occurs;
- artifact collection must use its own native handle-based containment checks while reading;
- real isolated-host tests must verify denial under the actual execution identity.

The resolver does not retain directory handles across process launch because the Windows process creation API accepts a current-directory pathname, not a directory handle. Any stronger design would require a different containment mechanism and a new decision.

## Alternatives considered

### Lexical path comparison only

Rejected. It cannot observe junction, symbolic-link, mount-point, or native normalization behavior.

### Standard-library `filepath.EvalSymlinks`

Rejected as the security boundary. It is useful application logic but does not expose the exact Windows handle/final-path checks or later native integration needed by the broker.

### Raw `syscall.NewLazyDLL` declarations

Rejected. Re-declaring Windows constants, handles, and call signatures locally would increase unsafe/native review surface for APIs already maintained by the Go project.

### Reject every reparse point

Not selected as the only rule. Final handle-derived containment directly rejects authority expansion while allowing an internal alias that remains within the same approved root. Subsystems with stronger read semantics, especially artifacts, may impose stricter per-entry rejection.

## Consequences

Benefits:

- native final-path evidence replaces lexical-only authorization;
- the dependency remains small, maintained, versioned, checksummed, and cgo-free;
- Windows-only code stays behind build constraints;
- link escape and root alias behavior can be exercised on a real Windows filesystem.

Costs and limitations:

- a new reviewed module dependency is added to `go.mod`/`go.sum`;
- native handle code and Windows path-prefix conversion require careful tests;
- resolution cannot by itself eliminate the pathname race described above;
- hosted Windows tests are real API/filesystem tests but are not evidence for installed-account ACL isolation.

## Verification requirements

- ordinary directory resolution within a configured root;
- rejection of files, missing paths, outside paths, root aliases, and a real link/reparse escape;
- non-echoing error tests;
- Windows hosted and local real-filesystem test output inspected;
- Linux tests/build remain clean with Windows code excluded by build constraints;
- cgo-free Windows/Linux build checks and public history safety scans.

## References

- Go package documentation — `golang.org/x/sys/windows`: https://pkg.go.dev/golang.org/x/sys/windows
- Microsoft — `CreateFileW`: https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilew
- Microsoft — `GetFinalPathNameByHandleW`: https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew
- Microsoft — Naming Files, Paths, and Namespaces: https://learn.microsoft.com/windows/win32/fileio/naming-a-file
