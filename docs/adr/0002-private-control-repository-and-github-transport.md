# ADR 0002 — Private Control Repository and GitHub Request/Result Transport

- Status: Accepted
- Date: 2026-09-02
- Scope: public/private repository boundary, remote request authority, GitHub event transport, and authoritative request/result publication

## Context

Agent Workstation Gateway (AWG) needs a GitHub-native transport that lets a trusted remote agent submit bounded command requests without giving that agent authority to rewrite control-plane code, manage Actions, administer runners or secrets, or forge the authoritative execution ledger.

ADR 0001 already requires a dedicated control/runner OS identity, a separate restricted execution identity, and a privileged local broker that has no GitHub credential. This ADR decides the repository and GitHub boundary above that local model.

The public source repository must remain safe to fork and run on disposable public CI. It is never the workstation control repository. The active workstation workflow exists only in a separate private repository selected by the workstation owner.

GitHub's built-in request mechanisms have materially different permission boundaries:

- creating an issue with a fine-grained token requires `Issues: write`;
- `workflow_dispatch` requires `Actions: write` and lets the caller select a branch or tag `ref`;
- `repository_dispatch` requires `Contents: write`, although the event itself selects the default branch;
- creating a deployment requires `Deployments: write` and lets the caller select a branch, tag, or commit SHA;
- creating check runs offers a narrower `Checks: write` model, but GitHub documents write access to the Checks REST API as a GitHub-App-only capability in practice;
- commit statuses have a narrow write permission but do not provide a useful bounded request payload channel by themselves.

The transport must be judged by the real authority behind those permission classes, not by names such as "dispatch" or "deployment".

## Decision summary

The default AWG v0.1 transport is:

```text
trusted remote requester
        |
        | create one issue containing a bounded request envelope
        | Issues: write + Contents: read on one private control repository
        v
PRIVATE CONTROL REPOSITORY
        |
        | issues: opened
        | workflow code selected from default branch
        v
GitHub-hosted accept job
        |
        | validate event snapshot as data
        | canonicalize + digest
        | create authoritative accepted-request ledger entry
        v
self-hosted execute job
        |
        | repository permissions: {}
        | no repository checkout
        | installed protected AWG control binary -> local broker
        v
restricted execution identity
        |
        | no GitHub/control credential
        v
requested workload
        |
        | bounded result bytes/files returned to control job as data
        v
GitHub-hosted finalize job
        |
        | narrow Contents: write publication authority
        v
create-once authoritative result ledger
```

The request issue is a submission envelope, not the authoritative accepted request. The control-owned ledger becomes authoritative before execution begins.

## Repository boundary

### Public source repository

The public source repository contains generic source, schemas, installers, documentation, tests, safe GitHub-hosted CI, and an **inert** private-control workflow template outside the active `.github/workflows/` location.

It must not contain an active workflow that targets a persistent self-hosted workstation runner. A public fork or pull request therefore has no route to a workstation.

### Private control repository

A workstation installation uses a dedicated private repository, conceptually:

```text
alice/awg-control
```

The private repository contains only control-plane data and fixed workflow configuration needed by the installed AWG version, for example:

```text
.github/workflows/execute-request.yml
control-version.json
ledger/requests/<request-id>/accepted.json
ledger/requests/<request-id>/result.json
```

The workflow must not execute mutable scripts, binaries, hooks, or configuration checked out from this repository. No repository checkout is required for the normal request path. The installed local AWG executable and local security policy are administrator-owned workstation files.

Bootstrap and `doctor` must positively verify that the control repository is private. Public visibility is a hard failure with no unsafe override in the initial release.

## Request authority and repository readership

The API credential recommended for a remote requester is scoped to exactly one private control repository with:

- `Issues: write` — submit a request by creating an issue;
- `Contents: read` — read the authoritative accepted/result ledger;
- metadata access implicitly required by GitHub.

It does **not** receive, by default:

- `Contents: write`;
- `Actions: write`;
- workflow-source write authority;
- `Deployments: write`;
- repository administration;
- Actions runner management;
- Actions secrets/variables management;
- any workstation-local credential.

A GitHub App installation token or a fine-grained personal access token can express this repository-scoped API permission set. A provider connector may expose broader residual authority; integrations must document the connector's actual installed permissions and must not describe broader authority as equivalent to the narrow AWG API profile.

There is one important GitHub semantic that cannot be hidden: **people with read access can create issues**. Therefore, for the default issue transport, every principal that can read this dedicated control repository must be treated as request-authorized.

Consequences:

- the control repository is dedicated to AWG and not shared merely for observability;
- bootstrap/doctor must inspect the effective repository access boundary and warn or fail when unexpected readers would become requesters;
- an organization repository with inherited/base read access is acceptable only when every effective reader is intentionally trusted to request workstation execution;
- on a personal-account private repository, collaborators already have write access, so collaborators are management-level trusted principals rather than read-only observers;
- result sharing with observers who must not request execution needs a different surface; it must not be achieved by granting them control-repository read access.

The workstation owner remains management-trusted and can of course modify the private control repository. The default requester credential is deliberately weaker.

## Why `issues: opened`

The private control workflow listens only to the `opened` activity type:

```yaml
on:
  issues:
    types: [opened]
```

GitHub documents the `issues` event as running with `GITHUB_SHA` at the last commit on the default branch and `GITHUB_REF` at the default branch, and the workflow file must exist on that default branch. The requester therefore does not choose the workflow ref.

The accept job consumes `github.event`, which GitHub defines as the full webhook payload that triggered the run. It reads the issue body from that event snapshot and **never re-fetches the current issue body** for execution.

This distinction makes later issue edits harmless to an already triggered request. An issue can be edited for display, but execution is bound to the original opened-event snapshot and then to the accepted ledger digest.

Issue titles, labels, comments, assignees, and later edits are not execution authority. The request body must be a strict protocol envelope and is treated only as data.

## Accepted-request ledger and digest

Before any self-hosted execution job can start, a disposable GitHub-hosted accept job validates the opened-event snapshot against protocol and policy limits.

The accept job validates at least:

- repository identity and private-control installation identity;
- event type/action;
- sender identity metadata;
- protocol version;
- request identifier syntax;
- request byte-size limit;
- schema shape and unknown fields;
- shell/working-directory fields at the protocol level;
- absence of any attempt to select workflow source/ref or management capability.

Protocol v1 defines the exact envelope and byte limits later. The transport-level rule is already fixed: the issue body has a substantially lower AWG limit than GitHub's maximum accepted content, and oversized requests fail before self-hosted execution. Large payloads are not smuggled through issue attachments or mutable external content in v0.1.

After validation, the hosted accept job canonicalizes the accepted request and computes a SHA-256 digest. It creates, using control-owned publication authority, a create-once record such as:

```text
ledger/requests/<request-id>/accepted.json
```

The record includes enough provenance to audit the acceptance decision, including:

- protocol version;
- validated request ID;
- canonical request digest;
- source issue number/node identity;
- sender numeric identity and login as observed in the event;
- workflow run/event provenance;
- control-template/source version expected by the installation;
- acceptance timestamp/state.

The canonical request bytes, not mutable issue state, define the execution identity.

### Create-once conflict rules

The ledger uses compare-and-create semantics rather than blind overwrite:

1. a previously unseen request ID may create one accepted record;
2. the same request ID with the same digest is a duplicate/recovery observation, not permission to execute a second copy;
3. the same request ID with a different digest is a conflict and fails closed;
4. a terminal result is create-once for the corresponding accepted digest;
5. retries/recovery create explicit attempt metadata rather than rewriting the accepted request.

GitHub workflow `concurrency` may reduce duplicate work but is not the correctness boundary. The authoritative create-once ledger and broker-side request/attempt state provide idempotency across races, workflow reruns, and multiple issues carrying the same request ID.

## Job-level permission split

### Hosted accept job

Runs on a disposable GitHub-hosted runner. It receives only the repository permission needed to publish the accepted ledger entry, normally `Contents: write` with all other unspecified permissions disabled.

It operates on the event snapshot and fixed workflow logic. It does not checkout mutable repository code. Accepted request bytes can be passed to the next job through a bounded workflow output or artifact after the ledger write succeeds.

### Persistent self-hosted execute job

Runs only in the private control repository and targets the dedicated AWG control runner labels. Its repository permission block is:

```yaml
permissions: {}
```

GitHub still creates job/runtime authentication material for Actions itself. That material remains in the trusted control/runner identity. The fixed workflow never forwards the runner process environment to the AWG broker, and the broker constructs a fresh allowlisted environment for the restricted execution identity.

The execute job:

- performs no repository checkout;
- does not receive repository publication authority;
- does not fetch current issue state;
- passes the already accepted bounded request to the protected, installed AWG control executable as data;
- receives broker/workload output as untrusted bounded data;
- may use the control job's Actions artifact channel for handoff, but arbitrary workload never receives the Actions service credential used by that channel.

This preserves ADR 0001 even if a generated command deliberately attempts to inspect GitHub or Actions variables.

### Hosted finalize job

A disposable GitHub-hosted finalizer receives the bounded execution result and owns the narrow repository write needed to create the authoritative result ledger entry.

This deliberately moves durable Git publication authority off the persistent workstation. The self-hosted runner and arbitrary workload do not need `Contents: write` merely to return a result.

The exact minimum additional read permission, if any, required by the chosen cross-job artifact implementation must be verified when the workflow template is implemented. It may not be "solved" by granting broad write permissions to the self-hosted job.

## Result authority and tamper semantics

A result is authoritative only after the hosted finalizer binds it to the accepted request digest and creates the control-owned result record.

The result record includes at least:

- request ID and accepted-request digest;
- execution attempt identity;
- installed AWG/control version observed by the broker;
- terminal status and exit/timeout/cancellation metadata;
- bounded stdout/stderr metadata and digests;
- artifact manifest/digests where applicable;
- finalization timestamp and workflow provenance.

The default requester has `Contents: read`, not `Contents: write`, so it cannot forge or silently rewrite accepted/result ledger files. Issue comments may later mirror human-friendly status, but comments are not the authoritative ledger.

A failed finalization is a distinct publication failure. It must not be reported as an ordinary command success merely because a self-hosted job produced output. Recovery can re-finalize the same accepted digest/attempt without re-executing a terminal workload.

The workstation owner or another repository-management principal can alter the ledger because those principals are explicitly trusted management authority. AWG does not claim to protect the owner from the owner.

## Source-version pinning

Requesters cannot choose the executable source revision.

Install/update is a local management operation that:

1. selects and verifies an exact public AWG release/commit;
2. installs protected local binaries/configuration for that version;
3. materializes the matching fixed control-workflow template into the private control repository;
4. records the control template/source version in protected local state and control metadata.

Normal requests call the installed protected executable. They never checkout an arbitrary public branch, issue attachment, or requester-selected commit for control-plane execution.

If real-hardware testing intentionally targets a public source commit, that is a separate trusted private smoke flow and the exact public SHA is selected by the smoke controller, not by an untrusted public event.

## Replay, concurrency, and availability

### Replay and idempotency

Issue creation is a submission event, not an exactly-once message queue. AWG therefore makes acceptance idempotent by stable request ID plus canonical digest.

A trusted administrator may rerun a workflow for recovery, but the default requester lacks `Actions: write`. A rerun observes the existing accepted/result state and must not blindly execute a completed request again.

### Concurrent submissions

Multiple request issues may open concurrently. Correctness does not depend on GitHub's scheduling order. Create-once ledger operations and local broker attempt ownership arbitrate duplicates. Future session ordering belongs to the protocol layer; the transport does not manufacture global ordering from issue numbers.

### Mutable envelope

Only the opened-event snapshot is eligible for acceptance. `issues: edited` is not a trigger. The workflow does not refetch issue content after acceptance. A changed issue body therefore cannot silently change work already admitted.

### Availability

The default transport depends on GitHub Issues and GitHub Actions availability. Opening an issue is not equivalent to acceptance: a request is accepted only after the hosted accept job creates the authoritative ledger record.

If GitHub delays or fails the workflow, no inbound fallback port is opened. Recovery uses the same request ID/digest and explicit ledger state. A future transport may improve availability, but must preserve the same authority boundary.

### Audit retention

The private ledger is the durable audit source. Actions logs/artifacts are supporting evidence with provider retention limits, not the sole record of request identity or terminal state. Secrets are never intentionally copied into the ledger merely for diagnostics.

## Alternatives considered

### `workflow_dispatch`

Rejected as the default. GitHub requires `Actions: write`, the caller supplies a branch/tag `ref`, and the Actions write permission class also covers materially broader workflow-run/management operations such as re-runs, cancellation, enable/disable, and log/run deletion. It is not a dispatch-only grant.

### `repository_dispatch`

Rejected as the default. It has attractive default-branch workflow semantics and a bounded custom payload, but GitHub requires `Contents: write` to create the event. That would give the requester precisely the repository-content authority this design keeps control-owned.

### Deployment events

Rejected as the default. `Deployments: write` is narrower than repository contents, but deployment creation is a deployment-management capability and accepts a caller-supplied branch, tag, or SHA. It also has deployment-specific merge/status semantics AWG does not need.

### Checks API

Deferred as a possible future GitHub-App-specific transport. `Checks: write` can be narrower than Issues plus repository readership, but GitHub documents Checks REST write operations as available to GitHub Apps rather than general authenticated users/OAuth clients. Making a custom GitHub App mandatory would reduce the generic connector/onboarding story for v0.1.

### Commit statuses

Not selected. `Commit statuses: write` is narrow, but a commit status contains state/context/description/target URL rather than a useful strict command envelope. Supplying the request bytes would require another writable channel and reintroduce authority elsewhere.

### Repository content/push transport

Rejected. Giving the requester `Contents: write` to append request files allows it to mutate the same repository namespace used for control metadata and, unless every future consumer remains perfect, creates an avoidable path from request authority toward control-code/data tampering.

### Issue comments

Not selected for initial submission. They add pull-request/comment distinctions and edit/delete lifecycle without reducing the underlying fact that repository readers can create issue activity. A fresh issue gives one natural immutable opened-event snapshot per submission.

## Security consequences

The chosen design intentionally accepts this bounded authority statement:

> Compromise of an effective reader/requester of the dedicated private control repository can authorize arbitrary workloads within the locally configured AWG execution authority, but does not automatically grant control-repository publication authority, Actions management, runner management, gateway administration, root/SYSTEM execution, human credentials, or unrelated filesystem authority.

That is why private visibility, reader auditing, restricted local execution, and control-owned result publication are all required together.

The public repository remains outside this authority chain. Its active workflows may use only disposable hosted runners and may never target the workstation.

## Verification requirements

Implementation of this ADR is not complete until automated and isolated tests prove, without printing secrets:

- bootstrap refuses a public control repository;
- bootstrap/doctor reports the effective reader/requester boundary;
- the narrow requester credential can create a request issue and read the authoritative ledger;
- the narrow requester cannot write contents, change workflow source, use Actions write operations, manage runners/secrets, deploy, or administer the repository;
- an opened request runs fixed default-branch workflow code;
- editing the issue after opening does not change the accepted digest;
- same-ID/same-digest retries do not produce duplicate terminal execution;
- same-ID/different-digest submissions fail closed;
- the hosted accept ledger entry exists before self-hosted execution starts;
- the self-hosted execute job performs no checkout and has no repository write permission;
- synthetic GitHub/Actions credential markers remain unavailable to arbitrary workload;
- the hosted finalizer can publish a result while the self-hosted job/workload cannot forge one;
- finalization failure remains distinguishable and recoverable without blind re-execution;
- public active workflows contain no `self-hosted` target or privileged public-PR execution path.

## References

Authoritative GitHub documentation reviewed for this decision:

- Events that trigger workflows: https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows
- Contexts reference (`github.event`): https://docs.github.com/en/actions/reference/workflows-and-actions/contexts
- REST API endpoints for issues: https://docs.github.com/en/rest/issues/issues
- Creating an issue (read access can create issues): https://docs.github.com/en/issues/tracking-your-work-with-issues/using-issues/creating-an-issue
- REST API endpoints for workflows (`workflow_dispatch` and workflow management permissions): https://docs.github.com/en/rest/actions/workflows
- REST API endpoints for workflow runs: https://docs.github.com/en/rest/actions/workflow-runs
- REST API endpoint for repository dispatch: https://docs.github.com/en/rest/repos/repos#create-a-repository-dispatch-event
- REST API endpoints for deployments: https://docs.github.com/en/rest/deployments/deployments
- REST API endpoints for check runs: https://docs.github.com/en/rest/checks/runs
- REST API endpoints for commit statuses: https://docs.github.com/en/rest/commits/statuses
- Workflow syntax (`permissions`): https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax
- `GITHUB_TOKEN`: https://docs.github.com/en/actions/concepts/security/github_token
- Permission levels for a personal-account repository: https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/repository-access-and-collaboration/permission-levels-for-a-personal-account-repository

## Follow-up decisions

Protocol schemas will define the exact request/result bytes, canonicalization, state machine, size limits, and session ordering. Private-control bootstrap will implement access auditing and the fixed workflow template. The implementation/runtime ADR will decide how the fixed hosted validation/finalization logic and local broker client are packaged.

Those later decisions may strengthen this transport but must not give the default requester `Contents: write` or `Actions: write`, make public source code an active workstation trigger, or move repository publication authority into arbitrary workload.
