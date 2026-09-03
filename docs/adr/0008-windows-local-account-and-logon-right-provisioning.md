# ADR 0008 — Windows Local Account and Logon-Right Provisioning

- Status: Accepted
- Date: 2026-09-03
- Scope: Initial Windows control/execution account creation, group membership, logon rights, secret ownership, and rollback

## Context

AWG needs two distinct local non-administrator identities before installed configuration can be bound to real SIDs. Silently adopting a same-named account is unsafe: it may belong to a human or another application, have unexpected memberships/rights, or make uninstall delete data that AWG did not create.

Account provisioning is an elevated local installation action. It is not part of the runner-facing broker protocol and no remote request may choose account names, SIDs, passwords, groups, or rights.

## Decision

Initial v0.1 installation is create-new-only for both configured local account names. Preflight requires both names to be absent before password generation or mutation. A future repair/adoption design must prove ownership from protected installed state and requires a separate decision.

The installer generates two independent 32-byte mutable passwords from `crypto/rand`. Generation guarantees upper-case, lower-case, digit, and punctuation classes, then cryptographically shuffles all positions. Password bytes are never formatted as a Go string by the transaction. Both are cleared when the account lease commits or rolls back; the composite installer additionally clears the execution password immediately after protected credential materialization.

The native boundary is constructed from the validated install specification and accepts only its control/execution names. `NetUserAdd` creates a normal standard local account with a non-expiring machine-generated password. The returned user SID is resolved natively. Its runtime token primary group is the account domain's Users group (`DOMAIN_GROUP_RID_USERS`); the installer derives that SID from the account SID and records it for exact token validation.

Each created account is separately added to the built-in local Users alias. Direct/indirect local-group enumeration must then report that alias only. This local membership SID is not the account-domain primary-group SID reported by a logon token. Any additional membership—including Administrators, Remote Desktop/Management, or `docker-users`—is a closed failure. Docker remains a later explicit capability transaction.

Fixed direct LSA rights are:

| Identity | Rights |
|---|---|
| control | `SeServiceLogonRight`, `SeDenyInteractiveLogonRight`, `SeDenyRemoteInteractiveLogonRight` |
| execution | `SeBatchLogonRight`, `SeDenyInteractiveLogonRight`, `SeDenyRemoteInteractiveLogonRight`, `SeDenyServiceLogonRight` |

No input supplies these strings. After `LsaAddAccountRights`, direct rights are enumerated and must equal the fixed set. Domain/local policy can still prevent logon; `doctor` and isolated E2E must test effective behavior.

`CreateAccount` reports whether NetAPI created the account even if later SID resolution fails. The orchestration lease records that fact before processing the error. Rollback deletes created accounts in reverse order and native deletion requires same-process transaction ownership. A pre-existing account is never a rollback target. Commit preserves accounts and clears both password buffers.

The execution password is consumed by the protected-state materializer from ADR 0007/WU016 and explicitly cleared before broker-service registration. The control password remains live only until the later runner-service installation step gives Windows service management the credential; it is not a workload or control-repository secret. ADR 0017 composes these lifetimes without prematurely committing the account lease.

## Alternatives considered

### Adopt matching existing local accounts

Rejected for initial installation. A matching name is not proof of ownership, SID, group policy, profile contents, or safe deletion semantics.

### Administrator-supplied passwords

Rejected as the default. It adds interactive secret entry, reuse risk, and logging/history hazards without helping unattended service identities.

### Add execution to Docker or remote-access groups by default

Rejected. Those are high-authority opt-ins, not ordinary tool availability.

### Give both accounts batch and service logon

Rejected. Each identity receives only its required positive logon right; explicit deny rights prevent the unused interactive/service modes.

## Consequences and evidence limits

Unit tests cover password class/length/clearing, pre-existing-name denial before generation, distinct SID binding, post-create failure tracking, reverse rollback, commit semantics, role-to-right closure, mutable UTF-16 clearing, and an actual non-mutating `NetUserGetInfo` query for a synthetic absent account.

Ordinary local and hosted tests do not create/delete accounts or change LSA policy. They therefore do not prove elevation, effective group memberships, effective deny rights, batch/service logon, profile creation, or cleanup on a real installed host. Those are isolated elevated smoke gates and must never be claimed from compilation or mocks.

## Verification requirements

- isolated create-new success for both synthetic accounts;
- exact SID and Users-only membership evidence without secret output;
- effective control service logon and execution batch logon;
- denied interactive/remote-interactive execution logon where testable;
- transaction rollback after an injected post-create failure;
- negative execution-account reads of protected broker/runner/human state;
- uninstall ownership proof before persistent account deletion.

## References

- Microsoft — `NetUserAdd`: https://learn.microsoft.com/windows/win32/api/lmaccess/nf-lmaccess-netuseradd
- Microsoft — `NetLocalGroupAddMembers`: https://learn.microsoft.com/windows/win32/api/lmaccess/nf-lmaccess-netlocalgroupaddmembers
- Microsoft — `LsaAddAccountRights`: https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-lsaaddaccountrights
- Microsoft — Account Rights Constants: https://learn.microsoft.com/windows/win32/secauthz/account-rights-constants
