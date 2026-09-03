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
- the canonical lowercase 40-hex source SHA embedded by its trusted build;
- the v0.1-pinned official Windows x64 runner archive; and
- a verified private-repository receipt, fixed runner name, and separate short-lived registration/removal tokens.

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
9. extract the pinned runner archive into a new protected control-only root;
10. configure exactly one repository runner through a direct, bounded, no-shell process and seal its generated credentials;
11. create and verify the fixed disabled-staged/automatic-final runner service under the control identity; and
12. return an uncommitted composite lease.

The protected-root lease refuses an existing installation root and never performs recursive deletion. Its state-store surface accepts only the three derived directories, execution credential, installation configuration, and broker image. It records native `created` outcomes even when post-create verification fails. Rollback removes only recorded exact protected files, then their owned empty directories.

Composite rollback deletes the runner service, attempts remote runner removal with the distinct removal token, removes exact create-owned runner state, then closes the broker service, protected root/image/state, workload filesystem changes, and accounts. Every close is attempted even after a cleanup failure.

The lease exposes only the SID-bound configuration and source SHA as copies. The control password has no public callback: the transaction makes one temporary mutable copy for `CreateServiceW`, clears it immediately, and the account lease clears its owned copy on commit or rollback.

Commit closes the verified service handle first while it is still rollback-capable. If that close fails, the entire transaction rolls back. The remaining concrete account/filesystem/root commits are in-memory ownership finalizers and are all attempted; account commit clears the control password. A reported impossible finalizer invariant failure does not falsely claim that an already committed service was rolled back.

The composite lease is not yet exposed by `awg install` and never starts either service. Private-repository creation/auditing and token acquisition remain bootstrap responsibilities outside this transaction.

## Consequences

- A create-new Windows installation has one ownership graph instead of independent name-based cleanup.
- Existing install roots, accounts, or services fail closed; repair, adoption, reinstall, and uninstall require separate designs.
- Execution plaintext lifetime ends after protected state materialization, while control plaintext remains limited to the uncommitted trusted setup transaction.
- Broker image destination/name, service policy, account rights, state paths, and stage order cannot be selected by request/spec fields.
- Unit/injected tests cover both image pins, the real broker build shape, exact stage order, every stage failure, cancellation, reverse rollback, cleanup failures, credential clearing, and commit edges.
- Ordinary Windows tests do not create accounts, rewrite real workload ACLs, create protected system state, register a service, or demonstrate effective cross-identity denial. Those remain isolated smoke requirements.
