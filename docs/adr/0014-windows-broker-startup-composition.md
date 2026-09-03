# ADR 0014: Windows Broker Startup Composition

## Status

Accepted.

## Context

The bounded broker session is safe only if its installed policy and native dependencies come from trusted local state. Allowing a request, service environment, or command line to choose individual configuration, credential, endpoint, identity, resolver, launcher, or executable paths would turn startup composition into a privileged confused-deputy boundary.

Windows machine-scoped DPAPI also does not bind the encrypted execution password to LocalSystem. The broker must independently verify the exact protected files at startup and again whenever it acquires the execution credential. Configuration authority must remain outside every filesystem subtree writable by the execution identity.

## Decision

`internal/platform/windows/brokerhost` is the sole Windows composition root for the real broker session dependencies. It accepts only an administrator-selected canonical non-root installation root and the installed gateway source SHA. `internal/installplan.WindowsLayout` derives the fixed `state/installation.json` and `state/execution-credential.dpapi` paths used by both installation planning and broker startup. No request or environment value selects a state path.

The reusable protected-state reader opens one exact path with no sharing and `FILE_FLAG_OPEN_REPARSE_POINT`. Through that handle it requires a regular nonempty disk file, the configured byte bound, one hard link, a canonical final path equal to the configured path, and the exact protected LocalSystem/Administrators descriptor. It snapshots attributes, volume/file identity, link count, size, and write time before and after a bounded read. Any mismatch fails closed, and rejected/consumed buffers are cleared. Credential acquisition invokes this reader again rather than relying on the startup check.

Startup proceeds in this order:

1. derive the fixed layout;
2. read and strictly decode the bounded protected installation configuration;
3. reject overlap between the installation root and every approved workload root, execution profile root, or execution temporary root;
4. validate the fixed protected credential file;
5. obtain the Windows directory from `GetSystemWindowsDirectoryW` and construct only matching `SystemRoot` and `WINDIR` safe-base entries;
6. construct the fixed `FileTokenSource`, mandatory-token Windows launcher, execution-token artifact collector, shared runner, native resolver, and bounded broker session;
7. create the fixed authenticated named-pipe listener last.

There is no current-user, current-environment, `os/exec`, unprotected-state, or alternate-listener fallback. Internal dependency seams exist only to exercise startup failure and ownership behavior in package tests; every dependency is mandatory and the exported constructor supplies only the native production implementations.

The runtime accepts one authenticated connection at a time through `HandleOne`. It passes the connection to the bounded session and closes it on every successful or failed session return. Partial listener construction is closed, and runtime close is idempotent. Runtime close also interrupts its active accepted connection so the service can bound shutdown of request/response I/O. The service loop owns repetition, cancellation, and SCM state reporting; those concerns do not broaden this composition boundary.

## Consequences

- Installation and runtime cannot drift to independently constructed protected-state paths.
- An execution-writable configured root cannot contain or contain the installation authority.
- Service or runner environment credentials are not projected into workload state merely because they exist in the broker process environment.
- Startup configuration and credential failures expose only coarse broker-host rules, not path, file content, credential data, or native diagnostic text.
- Ordinary Windows tests prove fixed derivation, strict decoding, overlap denial, minimal native environment projection, real dependency constructor compatibility, failure cleanup, and connection ownership. Ordinary user-owned files are intentionally rejected.
- These tests do not prove elevated protected-file convergence, LocalSystem service startup, successful installed-account batch logon, installed execution-account filesystem access, or denial to unrelated identities. Those remain isolated-host acceptance evidence.
