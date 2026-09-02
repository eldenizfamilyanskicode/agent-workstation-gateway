# ADR 0004 — Apache License 2.0

- Status: Accepted
- Date: 2026-09-02
- Scope: source and documentation licensing for the public project

## Context

Agent Workstation Gateway is intended to be broadly reusable infrastructure with external contributors and integrations. The project needs a permissive license that permits commercial and private use while providing a clear contribution and patent framework appropriate for security-sensitive infrastructure.

The two leading simple options considered for the initial public project were MIT and Apache License 2.0.

## Decision

The project is licensed under **Apache License 2.0**.

The repository root contains the complete standard license text in `LICENSE`. Contributions intentionally submitted for inclusion are accepted under the same license unless an explicitly documented exception applies to a third-party component.

## Why Apache-2.0

- It is permissive and allows commercial, private, and modified use subject to its notice/license conditions.
- It includes an explicit contributor patent license and patent-termination provision, which is useful for infrastructure expected to receive external contributions.
- It defines contribution licensing directly, reducing ambiguity for ordinary pull-request contributions.
- It is widely understood by open-source tooling and package ecosystems.

## Alternatives

### MIT

MIT is shorter and highly permissive, but it does not contain the same explicit patent grant and contribution framework. The additional Apache-2.0 terms are acceptable for this project.

### Copyleft licenses

Strong copyleft was not selected because the project goal is broad adoption as workstation infrastructure across commercial and open-source environments. This decision can be revisited only with explicit governance and compatibility analysis.

## Third-party code

This license decision does not relicense third-party code. New dependencies or copied source must have compatible licensing, and required notices must be retained. Avoid vendoring source merely for convenience.

## Consequences

- Release artifacts and source distributions include the Apache-2.0 license text.
- A later `NOTICE` file is added only when the project has attribution notices that actually require it.
- Contributor guidance can state that submitted contributions are licensed under Apache-2.0.
