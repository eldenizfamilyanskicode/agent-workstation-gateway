# AGENTS.md

## Purpose

Agent Workstation Gateway is security-sensitive infrastructure. Treat repository boundaries, OS identity separation, credential isolation, and verification evidence as product requirements rather than optional hardening.

## Read before changing security-sensitive behavior

Read the relevant documents before implementation or review:

- `docs/threat-model.md`
- `docs/adr/0001-control-execution-identity-and-credentials.md`
- `docs/adr/0002-private-control-repository-and-github-transport.md`
- `docs/adr/0003-go-runtime-and-packaging.md`

Read newer ADRs that affect the subsystem you are changing.

## Non-negotiable boundaries

- This public source repository must never be the control repository for a persistent workstation runner.
- Active workflows in this repository may use only disposable public CI infrastructure. Do not add `runs-on: self-hosted` or `pull_request_target` without an explicit security redesign and review.
- Trusted control-plane credentials, runner credentials, human GitHub credentials, browser credentials, and unrelated personal files must not become readable merely because a workload is executed.
- Arbitrary workload execution must happen under a restricted execution identity, separate from the trusted control identity.
- The privileged broker must stay narrow. It is not a generic root/SYSTEM shell, filesystem proxy, repository client, or updater driven by request data.
- Control workflow/request content is data. Never interpolate requester-controlled text into trusted workflow shell source.
- The public repository must contain no personal machine identifiers, private project names, private runtime logs, registration tokens, credential files, or real secret values. Use synthetic examples such as `alice`, `example-control`, `C:\Users\Alice\Projects`, and `/home/alice/projects`.
- Never print a secret to prove that it exists. Check only presence/readability and report booleans or denial.

## Implementation direction

- Security-critical product code is Go.
- Keep the base distribution self-contained and cgo-free unless a later ADR justifies otherwise.
- Platform-specific Windows and Linux behavior belongs in native platform packages rather than lowest-common-denominator abstractions.
- PowerShell and POSIX shell are thin bootstrap/automation layers, not the privileged policy implementation.
- Python is allowed for development tooling only when justified; use `uv` for Python tooling.
- Windows and Linux are first-class targets. Cross-compilation proves a build, not an OS security boundary.

## Development discipline

- Preserve unrelated changes.
- Prefer small, coherent commits that can be reviewed and reverted independently.
- Keep documentation aligned with the implementation in the same logical change.
- Pre-v0.1 has no compatibility obligation unless an ADR or released contract explicitly creates one. Prefer a clean design over compatibility shims.
- Keep dependencies deliberately small. Prefer the standard library and narrowly scoped maintained packages over broad frameworks.
- Treat new native dependencies, cgo, privileged capabilities, Docker access, and updater behavior as explicit design decisions.

## Verification

Do not claim a change is tested, verified, secure, Windows-tested, Linux-tested, or E2E-tested unless the corresponding output was actually inspected.

For relevant changes, run and inspect:

- formatting/static checks;
- unit and integration tests;
- public-safety and workflow-safety checks;
- platform-specific real-host tests for native security behavior;
- negative tests for forbidden credential/filesystem access;
- staged diff and published-history scans before release-sensitive changes.

When Go code exists, the normal baseline is `gofmt` plus `go test ./...`, with additional security tooling defined by the repository. Do not weaken ACLs, identity separation, or safety checks merely to make a failing test pass.

## Public workflow rule

A public pull request must have no execution route to a maintainer's persistent workstation. Real hardware testing, when needed, is initiated only by a separate trusted private smoke system against an explicitly selected public commit SHA.
