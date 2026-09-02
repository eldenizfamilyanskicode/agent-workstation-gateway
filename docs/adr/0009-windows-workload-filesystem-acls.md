# ADR 0009 — Windows Workload Filesystem ACLs

- Status: Accepted
- Date: 2026-09-03
- Scope: Approved development roots and dedicated execution profile/temp roots

## Context

The execution account needs filesystem authority to do useful work, but it must not gain authority over gateway state merely because a request names a path. Lexical approved-root validation is not an access grant, and recursively replacing an administrator's existing project ACLs would be both destructive and difficult to roll back safely.

ACL provisioning is therefore an elevated local installation action driven only by the validated installed configuration. It is not a broker operation. No remote request can supply an ACL path, SID, access mask, inheritance flag, owner, or rollback instruction.

## Decision

The Windows installer uses one rollback-capable filesystem lease after it has resolved the dedicated execution SID.

For every approved development root:

- the root must already exist as a canonical local directory;
- the native boundary opens it without sharing, with `FILE_FLAG_OPEN_REPARSE_POINT`, rejects reparse points, and requires its same-handle final path to equal the configured path;
- the existing owner, DACL-protection state, and ACEs for other principals are retained;
- all direct ACEs for the execution SID are revoked and replaced by one direct container/object-inheritable allow ACE with Windows Modify rights (`FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE`);
- the execution SID is forbidden as the root owner, inherited/conflicting execution ACEs fail closed, and unsupported/conditional ACE forms fail closed rather than being interpreted incompletely;
- broad principals known to be present in the batch-logon token—Everyone, Authenticated Users, built-in Users, Local Account, and Batch—may not grant ACL/owner management or deny the fixed execution rights.

This changes only the approved-root directory DACL. It does not recursively rewrite protected child ACLs. Existing children that intentionally block inheritance may remain inaccessible and must be reported by later `doctor`/smoke checks rather than fixed through a broad recursive privileged traversal.

Profile and temporary roots use a stricter policy. Their parent must already be a canonical non-reparse directory. A missing leaf is created with a short-lived protected bootstrap DACL containing the trusted installer identity so the creator can retain an open verified handle even when its Administrators group is filtered. Before the native method returns, that bootstrap ACE is removed.

The final profile/temp DACL is protected from parent inheritance and contains exactly:

| Principal | Access | Inheritance |
|---|---|---|
| LocalSystem | Windows `FILE_ALL_ACCESS` (`0x1f01ff`) | container and object |
| built-in Administrators | Windows `FILE_ALL_ACCESS` (`0x1f01ff`) | container and object |
| configured execution SID | Modify (`0x1301bf`) | container and object |

The execution mask deliberately excludes `WRITE_DAC`, `WRITE_OWNER`, and privileged system-security access. The execution SID may not own either root.

Every returned native change retains the same verified directory handle plus the original descriptor needed for rollback. A failed multi-root transaction restores completed changes in reverse order. Existing descriptors are restored with their original protected/unprotected state. Only a leaf positively created by this transaction is removed on rollback. Commit closes handles and discards rollback state.

## Alternatives considered

### Replace approved-root DACLs with the exact profile/temp policy

Rejected. It would remove administrator/human/project ACLs and could lock out legitimate users or tools.

### Recursively grant the execution SID across every descendant

Rejected for v0.1. It expands privileged traversal, link/race exposure, rollback volume, and the chance of rewriting intentionally protected content. Inheritance plus effective-access diagnostics is narrower.

### Let a request ask the broker to grant access to its working directory

Rejected. That would turn the privileged broker into an ACL proxy and make approved roots requester-controlled in practice.

### Grant Full Control to the execution identity

Rejected. The workload needs file/directory modification, not authority to rewrite the root security boundary.

## Consequences and evidence limits

The platform-neutral transaction tests prove installed-target selection, reverse rollback, rollback-error handling, and commit-time state discard. Windows tests use only fresh temporary synthetic directories: they apply and verify a real approved-root descriptor through the owned handle, restore the original descriptor, create an isolated leaf with the exact DACL, and remove that same created leaf on rollback. Tests also reject broader execution rights and broad-principal ACL management.

Those tests do not use the installed `awg-exec` account and do not prove its effective token access, inherited access to a populated project, denial of protected gateway/human files, or elevated install behavior. Those remain isolated real-host gates. No ordinary test changes a real project, human profile, or gateway-state ACL.

## Verification requirements

- installed execution token can create, modify, execute, and delete synthetic content under an approved root;
- execution token cannot change the approved-root/profile/temp DACL or owner;
- execution token is denied broker binaries, configuration, DPAPI ciphertext, runner state, and a synthetic human-secret file;
- pre-existing owner/human access to an approved root remains effective after install and rollback;
- a reparse/alias target and a conflicting inherited execution ACE fail closed;
- uninstall restores descriptors it owns and removes only empty dedicated roots proven to be installation-owned.

## References

- Microsoft — File Security and Access Rights: https://learn.microsoft.com/windows/win32/fileio/file-security-and-access-rights
- Microsoft — `SetSecurityInfo`: https://learn.microsoft.com/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo
- Microsoft — `SetEntriesInAclW`: https://learn.microsoft.com/windows/win32/api/aclapi/nf-aclapi-setentriesinaclw
- Microsoft — ACE Inheritance: https://learn.microsoft.com/windows/win32/secauthz/ace-inheritance-rules
