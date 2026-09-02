# Reference Runtime Audit

This note records lessons from an existing private reference implementation. It intentionally contains only generic findings suitable for a public repository. It is not a code-copying plan and does not preserve private operational history.

## Scope reviewed

The audit covered the control workflow, request validation, shell execution, result publication, artifact collection, runner installation, persistent-process helpers, and executor tests.

## Concepts worth retaining

- **Durable request/result ledger.** A request is a complete immutable unit with a stable ID, and execution materializes a structured result beside captured output.
- **Session isolation at the control-plane level.** Independent session branches allow ordering within one session without imposing repository-wide serialization.
- **Strict protocol validation.** Unknown fields, invalid shell/script combinations, malformed IDs, oversized limits, and unsafe artifact paths are rejected before execution.
- **Explicit failure semantics.** Success, command failure, timeout, invalid request, runtime infrastructure failure, and artifact-publication failure remain distinguishable.
- **Bounded output capture.** stdout and stderr are captured independently, size-limited in Git-visible results, and can retain fuller diagnostics outside those bounded files.
- **Artifact manifests.** Artifact selection is relative to the declared working directory, rejects traversal, skips link-like filesystem escapes, applies count/size limits, and records hashes plus useful metadata.
- **Result finalization before surfacing failure.** A failed command should still publish a durable result before the orchestration job reports failure.
- **Persistent development-process lifecycle.** Explicit start/status/stop/logs is useful for local servers that must outlive one request.
- **Checked upstream downloads.** Installer components obtained from upstream should be verified against an authoritative digest when one is available.

## Architecture that must be redesigned

### 1. Public source and executable authority must be separate

The public source repository must never host an active workflow that targets a persistent workstation runner. Installation must materialize the execution workflow only in a user-owned **private** control repository.

### 2. Runner/control identity must not equal workload identity

A GitHub runner needs control-plane authority: runner registration state, a control checkout, and permission to publish results. Arbitrary requested commands do not need those capabilities. The new gateway therefore needs a distinct restricted execution identity, with the control identity acting only as launcher/orchestrator.

### 3. Workload environment must be constructed, not inherited

A normal child process inherits its parent environment unless explicitly changed. That is unacceptable when the parent is a GitHub Actions runner. The execution launcher must build an allowlisted environment from scratch and exclude GitHub, Actions, runner-management, installer, and human-session credentials. Presence checks must never print credential values.

### 4. Control checkout credentials must not leak into execution

The private control template should use checkout settings that do not persist workflow credentials. More importantly, the execution identity must not be able to read the runner installation, control checkout metadata, temporary workflow files, credential helpers, or human GitHub CLI state.

### 5. Working-directory authority needs explicit roots

An absolute existing directory is not enough authorization. Each installation should define approved development roots such as:

```text
C:\Users\Alice\Projects
/home/alice/projects
```

Every working directory must be canonicalized and proven to remain within an approved root, including link/reparse-point handling. The execution identity should receive filesystem permissions only for those roots.

### 6. Powerful local capabilities are opt-in

Docker or equivalent daemon control is effectively host-level authority on many systems. Installation must never grant it merely because the software is present. The same principle applies to other high-privilege local services.

### 7. Human credentials are not runtime dependencies

Human browser profiles, password stores, SSH material, Git credential stores, and interactive GitHub CLI authentication must remain outside the execution identity. Management credentials may be used transiently by the installer/control plane but never passed to requested commands.

### 8. Persistent processes need the same boundary

Removing a runner cleanup marker is useful for intentionally persistent development processes, but it is not isolation. Background processes must run under the restricted execution identity, use the sanitized environment, inherit the same allowed-root policy, and have durable ownership metadata plus stale-process cleanup.

### 9. Process termination is platform-specific

The protocol can expose one timeout contract, but implementation must use native semantics: Windows process-tree termination on Windows and process groups with TERM/grace/KILL on Linux. Linux should not be a transliteration of a PowerShell implementation.

### 10. Machine-specific assumptions must become configuration

Installation roots, account names, development roots, tool locations, runner labels/counts, and optional capabilities must not be hardcoded. Defaults should be conservative, especially a single runner for a normal installation.

## Test gaps the new project must close

The reference implementation has useful coverage for exit-code preservation, timeout, output truncation, malformed requests, artifact limits, path traversal, link/reparse avoidance, and artifact finalization. The new project additionally needs explicit negative tests proving that arbitrary workload cannot:

- observe GitHub/Actions management credentials;
- read runner credential files or the private control checkout;
- use a persisted checkout credential;
- read human GitHub CLI or browser state;
- escape an approved development root;
- gain Docker access unless explicitly enabled;
- leave descendants running after timeout/cancellation unless they were deliberately registered as persistent processes.

## Design direction carried forward

The public gateway should preserve the reference implementation's durable protocol ideas and verification discipline, while replacing its trust boundary. The defining invariant is:

```text
trusted control plane
        |
        | launches with an allowlisted environment
        v
restricted execution identity
        |
        +-- explicitly approved development roots
        +-- explicitly enabled local capabilities
        +-- no control-plane or human credentials
```

This audit is intentionally limited to lessons from the reference implementation. The threat model, identity design, credential model, platform strategy, and implementation-language choice are separate Phase 0 decisions.
