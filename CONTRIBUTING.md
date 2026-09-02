# Contributing

Agent Workstation Gateway is pre-release security-sensitive infrastructure. Contributions are welcome when they preserve the repository's public/private authority boundary and are scoped so they can be reviewed carefully.

## Before you change code

1. Read `AGENTS.md`.
2. Read `docs/threat-model.md` and the ADRs relevant to your change.
3. Keep public examples synthetic. Do not paste workstation logs, private repository names, real credentials, personal paths, or secret-bearing environment output.
4. For a security vulnerability, follow `SECURITY.md` instead of opening a detailed public issue.

## Change discipline

- Prefer small logical commits and focused pull requests.
- Preserve unrelated work.
- Update documentation together with behavior changes.
- Avoid compatibility shims before v0.1 unless an accepted contract requires them.
- Keep dependencies small and justified.
- Security-critical implementation code is Go; platform shells are limited to thin bootstrap/automation responsibilities.
- If Python development tooling is justified, use `uv`.

## Public CI safety

Do not add a public workflow that targets `self-hosted` runners. Do not use `pull_request_target` as a convenience path for executing contributor code. Public pull requests must remain unable to reach a maintainer's persistent workstation.

## Testing expectations

Run the narrowest relevant checks first, then broader checks appropriate to the change. Inspect actual outputs before claiming success.

Security-boundary changes normally require:

- unit/integration tests;
- negative access tests;
- public-safety/workflow-safety checks;
- real Windows or Linux verification for OS-specific identity, ACL, service, socket, or process semantics;
- documentation updates describing the behavior and limitations.

Cross-compilation alone is not platform verification.

## License

By intentionally submitting a contribution for inclusion in this project, you agree that it is provided under the Apache License 2.0 unless explicitly stated otherwise for compatible third-party material.
