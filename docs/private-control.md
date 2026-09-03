# Private control repository

Agent Workstation Gateway uses a dedicated private GitHub repository as its request and result transport. The public source repository is never a runner control repository and its active workflows remain GitHub-hosted only.

The v0.1 control flow is fixed:

1. A requester opens an issue whose body is one strict protocol-v1 request object.
2. A GitHub-hosted job reads the immutable `issues: opened` event, validates and canonicalizes the request with the pinned `awg-control` binary, verifies private visibility through the GitHub API, and creates `ledger/requests/<request-id>/accepted.json` without overwrite semantics.
3. A repository-permission-free workstation job performs no checkout. It passes the accepted record as data to the protected installed `awg.exe`, which talks to the local broker and executes under the restricted execution identity.
4. The workstation job uploads the bounded response using an immutable-pinned official artifact action. The arbitrary workload never receives the runner or artifact-service environment.
5. A GitHub-hosted job validates the execution report against the accepted record and creates `ledger/requests/<request-id>/result.json` without overwrite semantics.

The inert source template is stored under `templates/control-repository`. GitHub does not activate workflows from that location. Bootstrap renders it into `.github/workflows/execute-request.yml` only in the selected private control repository, with the exact hosted helper URL/digest, gateway source SHA, and protected installation root.

The accepted/result ledger is authoritative. An issue body, Actions log, or temporary artifact is not. Reusing a request ID causes the create-once publication to fail before workstation execution; it does not authorize a second attempt.

The hosted `awg-control` process consumes `GITHUB_TOKEN` from its environment and removes the variable before use. It reports only closed error categories and never prints the token, issue body, request script, repository response, or local input paths. The workstation job has `permissions: {}` and does not run the hosted publication helper.

The default requester authority remains one private repository with `Issues: write` and `Contents: read`. Every effective reader of the dedicated repository is request-authorized because GitHub permits readers to create issues. Bootstrap and doctor therefore treat unexpected readers and non-private visibility as failures, not warnings.
