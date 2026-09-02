# Security Policy

Agent Workstation Gateway is security-sensitive infrastructure because it mediates trusted remote authority and local command execution.

## Current support status

The project is pre-release. There is no supported stable version yet, and the repository must not be treated as production-ready until an explicit release states otherwise.

## Reporting a vulnerability

Please do not publish exploit details, credentials, private workstation information, or reproduction data containing secrets in a public issue.

Preferred reporting path:

1. Use GitHub private vulnerability reporting / a private security advisory for this repository when that option is available.
2. If no private reporting entry point is available, open a minimal public issue requesting a private contact channel. Do not include sensitive technical details in that issue.

A useful private report includes the affected revision/version, security boundary involved, minimal reproduction, expected versus actual behavior, impact, and any safe mitigation you have identified. Never include real secret values when a boolean/readability check is sufficient.

## Security boundaries contributors must preserve

- The public source repository does not control a persistent workstation runner.
- Workstation execution authority belongs only to a separate private control plane with trusted writers.
- Arbitrary workload execution is separated from the trusted control identity and management credentials.
- The privileged broker is a narrow policy boundary, not a generic privileged shell.
- Active public CI uses disposable hosted infrastructure and cannot route public pull-request code to a maintainer workstation.
- Examples and tests use synthetic identities, paths, and credentials.

See `docs/threat-model.md` and the accepted ADRs in `docs/adr/` for the current architectural security model.

## Not a sandbox

AWG is designed to restrict the authority of gateway-executed workloads relative to gateway management authority. It is not a general malware sandbox and does not make arbitrary untrusted internet code safe to execute.

## Security-sensitive changes

Changes affecting credentials, identity transitions, privileged IPC, filesystem boundaries, workflow authority, updater/install behavior, process lifetime, or artifact traversal require targeted negative tests and platform-appropriate verification. Do not remove a security check merely to make a test green.
