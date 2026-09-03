# ADR 0017: Windows Create-New Installer Transaction

## Status

Accepted.

## Context

Windows account, filesystem, protected-state, broker-service, and service-registration boundaries already own their local rollback rules. Calling them independently would still permit a partially installed gateway, premature credential clearing, or deletion by reconstructed names rather than active transaction ownership.

The control-account password also has a different lifetime from the execution-account password. Execution launch material can be cleared immediately after DPAPI state is written. The control credential must remain available only long enough for a later trusted runner-service installer to give Windows SCM the logon credential. Committing the accounts before that future step would make the generated credential unavailable without resetting it.

## Decision

`internal/platform/windows/installer` implements a create-new-only composite lease. It accepts:

- the strict validated Windows install specification;
- one trusted in-memory `awg-broker.exe` image;
- the canonical lowercase 40-hex source SHA embedded by its trusted build.

Before native mutation, input is copied and pinned. The image must be nonempty and at most 256 MiB, be a PE32+ AMD64 executable rather than a DLL, and contain the exact canonical source SHA. This is a structural/source-binding check, not artifact authenticity: the future release/bootstrap path must verify a published digest/signature/provenance before supplying bytes to this trusted installer boundary.

The transaction executes this fixed sequence:

1. read-only query of the one fixed service name;
2. create-new control/execution accounts and bind their native SIDs;
3. converge only configured workload/profile/temp filesystem leases;
4. create a new protected installation root plus fixed `bin` and `state` children;
5. atomically create and independently validate the fixed protected broker image;
6. seal and create the fixed execution credential, then create canonical installed configuration;
7. clear the execution password immediately;
8. create and verify the fixed disabled-staged/automatic-final LocalSystem broker service;
9. return an uncommitted composite lease.

The protected-root lease refuses an existing installation root and never performs recursive deletion. Its state-store surface accepts only the three derived directories, execution credential, installation configuration, and broker image. It records native `created` outcomes even when post-create verification fails. Rollback removes only recorded exact protected files, then their owned empty directories.

Composite rollback closes service, protected root/image/state, workload filesystem changes, and accounts in reverse order. Every close is attempted even after a cleanup failure, and the returned rule reports incomplete rollback without exposing native paths or credentials.

The lease exposes the SID-bound configuration and source SHA as copies. `UseControlPassword` supplies a temporary mutable copy to one synchronous trusted consumer and clears that copy on both success and error. The lease-owned control credential remains until commit/rollback and is never formatted as a string by this layer.

Commit closes the verified service handle first while it is still rollback-capable. If that close fails, the entire transaction rolls back. The remaining concrete account/filesystem/root commits are in-memory ownership finalizers and are all attempted; account commit clears the control password. A reported impossible finalizer invariant failure does not falsely claim that an already committed service was rolled back.

The composite lease is not yet exposed by `awg install`. A later runner/bootstrap transaction must consume the control credential and extend the trust decision before calling commit. This unit does not start the broker, select/create a private repository, install a GitHub runner, or accept network credentials.

## Consequences

- A create-new Windows installation has one ownership graph instead of independent name-based cleanup.
- Existing install roots, accounts, or services fail closed; repair, adoption, reinstall, and uninstall require separate designs.
- Execution plaintext lifetime ends after protected state materialization, while control plaintext remains limited to the uncommitted trusted setup transaction.
- Broker image destination/name, service policy, account rights, state paths, and stage order cannot be selected by request/spec fields.
- Unit/injected tests cover input pinning, the real broker build shape, exact stage order, every stage failure, partial receipts, cancellation after service creation, reverse rollback, cleanup failures, temporary credential-copy clearing, and commit edges.
- Ordinary Windows tests do not create accounts, rewrite real workload ACLs, create protected system state, register a service, or demonstrate effective cross-identity denial. Those remain isolated smoke requirements.
