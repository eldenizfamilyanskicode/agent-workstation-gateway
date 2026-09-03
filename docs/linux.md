# Linux Installation and Runtime

AWG v0.1 targets x86-64 Linux hosts using systemd. WSL2 is supported when the distribution boots with systemd enabled.

## Prerequisites

- a root-capable administrative shell;
- systemd and procfs;
- `getfacl` and `setfacl` (usually the `acl` package);
- the official GitHub Actions runner OS dependencies for the distribution (the pinned runner archive provides `bin/installdependencies.sh` for administrators to inspect and run before installation);
- GitHub CLI authenticated as the owner of a dedicated private control repository;
- the pinned AWG release binaries and official GitHub Actions runner archive.

Go is a build dependency only. Installed AWG binaries and workloads do not require a Go toolchain.

For v0.1, download `actions-runner-linux-x64-2.337.0.tar.gz` only from the official [`actions/runner` v2.337.0 release](https://github.com/actions/runner/releases/tag/v2.337.0). Before installation require an exact size of `226430031` bytes and SHA-256 `70920811a4f8ad4328818682bca5c6469c1c942fab52448868071d0063816613`. Also verify the AWG archive and hosted control helper against the release's `SHA256SUMS` before running either one.

## Plan first

Create a specification from [`config/examples/v1/linux-install.json`](../config/examples/v1/linux-install.json), using synthetic or host-appropriate paths and two new dedicated account names. Review the mutation-free plan:

```bash
./awg install --dry-run --spec ./linux-install.json
```

The installation root, derived runner root, execution profile, and execution temp root must not already exist. Approved roots must already exist as canonical directories and must not be symlinks.

## Install

Run the matching release executable as root and provide the exact pinned inputs:

```bash
sudo ./awg install \
  --spec ./linux-install.json \
  --repository alice/awg-control \
  --broker-image ./awg-broker \
  --control-image ./awg \
  --runner-archive ./actions-runner-linux-x64.tar.gz \
  --hosted-control-url https://github.com/eldenizfamilyanskicode/agent-workstation-gateway/releases/download/v0.1.0/awg-control_0.1.0_linux_amd64 \
  --hosted-control-sha256 <digest-from-SHA256SUMS> \
  --create-repository
```

Use the URL and SHA-256 published for the same AWG source commit. Installation hard-fails for a public repository, mismatched binaries, an unpinned runner archive, existing owned paths, existing identities, or missing platform dependencies.

The mutating command creates two system users/groups, protected state, the restricted runner, fixed systemd units, and explicit ACLs. Registration tokens remain in memory and are not written to configuration or logs.

## Diagnose and remove

Run the matching release executable as root:

```bash
sudo ./awg doctor --installation-root /opt/agent-workstation-gateway
sudo ./awg uninstall --installation-root /opt/agent-workstation-gateway
```

`doctor` checks source binding, protected ownership/modes, identities, ACLs, runner credential denial, exact unit definitions/effective hardening, running services, socket policy, private-repository visibility, control-file hashes, and the registered runner.

`awg version` reports the release version and exact embedded public source SHA without reading installed state. A successful `doctor` report includes the same fields alongside its boundary booleans.

`uninstall` repeats the fail-closed installed and remote-state checks before mutation. It removes the registered runner and installer-owned control files, disables services, restores the saved approved-root ACLs, removes AWG-owned roots and identities, and preserves the private repository and its request/result ledger. Run it from the matching release binary outside the installation root.

## Upgrade

v0.1 has no in-place updater. Run `doctor`, then uninstall with the matching old release binary outside the installation root. Verify the new release assets and reinstall with the same reviewed specification and private repository. The ledger and development-root contents remain, but the gateway is offline during the transition. Finish with `doctor` and one minimal request. See [ADR 0022](adr/0022-v0.1-release-and-upgrade.md).

## Security boundary

The control service can reach the fixed Unix socket but the broker additionally authenticates its exact UID. Workloads run with the separate execution UID/GID, no supplementary groups, no capabilities, and no-new-privileges. They receive a clean environment and can enter only approved development roots. Artifact collection uses the same execution identity.

Docker membership or another high-authority capability is not part of the base profile. AWG is not a sandbox for hostile code; it narrows a trusted agent's workstation authority.
