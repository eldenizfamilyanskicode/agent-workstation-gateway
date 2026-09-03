# Agent Workstation Gateway v0.1.0

First supported release for trusted development-agent workloads on Windows x64 and systemd-based Linux x64.

Highlights:

- separate trusted control and restricted execution OS identities;
- hard enforcement of a dedicated personal private GitHub control repository;
- narrow authenticated broker IPC and approved-root execution policy;
- foreground execution, bounded output/artifacts, timeout cleanup, and explicit background lifecycle;
- native Windows service/token/ACL/Job Object implementation;
- native Linux systemd/UID/POSIX ACL/Unix socket/process-group implementation;
- fail-closed install, doctor, uninstall, and documented uninstall/reinstall upgrade flow;
- strict protocol-v1 schemas and authoritative accepted/result ledger;
- hosted-only read-only public CI, pinned Actions, module integrity, vulnerability, and public-history safety gates.

Important limitations:

- AWG trusts the requesting agent and is not a malware sandbox.
- v0.1 supports Windows x64 and Linux x64 only.
- The default control repository must be personal, private, and exclusive to the authenticated owner.
- Docker and other host-powerful capabilities are not granted.
- Release checksums share the GitHub release channel and are not independently signed or transparency logged.

