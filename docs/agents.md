# Agent Integration

AWG is model- and vendor-neutral. An agent integration needs only an authenticated way to create an issue and read repository/Actions results in the user's dedicated **private** control repository. It must not receive workstation administrator access, the runner registration credential, or gateway state.

## Required agent behavior

Give the agent these values through its own trusted configuration:

- private control repository, for example `alice/example-control`;
- approved workload roots and the shell names configured by the workstation owner;
- an actor identifier and a strategy for unique `request_id`, `session_id`, and `process_id` values.

Require the agent to follow these rules:

1. Never use the public AWG source repository as a control repository.
2. Create an issue whose body is exactly one protocol-v1 JSON object, without Markdown fences or commentary.
3. Never change `.github/workflows/execute-request.yml`, `control-version.json`, or `ledger/`.
4. Never place credentials or unrelated private data in a request, script, title, output, or artifact.
5. Request only a configured shell and an approved working directory. Treat a rejection as a boundary decision, not a reason to widen ACLs.
6. Read `ledger/requests/<request_id>/result.json` as the authoritative outcome. Use its workflow run ID/attempt to download the bounded response artifact when stdout, stderr, or returned files are needed.
7. Report the actual `command_status`, exit code, output truncation flags, artifact omissions, and finalization outcome. Do not call an uninspected run successful.

GitHub documents non-interactive issue creation with `gh issue create --repo OWNER/REPO --title TITLE --body BODY`: [Creating an issue](https://docs.github.com/en/issues/tracking-your-work-with-issues/using-issues/creating-an-issue). A connector or API may perform the same operation if its repository scope is equally narrow.

## Minimal foreground request

The actual issue body contains raw JSON like this synthetic Linux example:

```json
{
  "protocol_version": 1,
  "request_id": "build-20260903-001",
  "session_id": "build-20260903",
  "actor": "alice-agent",
  "operation": "execute",
  "process_id": "",
  "shell": "bash",
  "working_directory": "/home/alice/projects/demo",
  "script": "set -eu\ngo test ./...",
  "timeout_seconds": 900,
  "max_output_bytes": 262144,
  "artifacts": []
}
```

For Windows, use a configured shell such as `pwsh` and a canonical path such as `C:\\Users\\Alice\\Projects\\demo`. Every field is required. Lifecycle operations and all limits are defined in [protocol v1](protocol-v1.md).

## Reusable instruction block

Replace only the synthetic repository/path values, then place this concise block in the agent's supported project-instruction mechanism:

```text
Use Agent Workstation Gateway only through my dedicated PRIVATE control repository alice/example-control. Never target the public AWG source repository and never edit the private workflow, control-version.json, or ledger. Submit exactly one strict protocol-v1 JSON object per issue. Use unique lowercase request/session/process IDs, only configured shells, and only approved working directories. Never include credentials or unrelated private data. Treat boundary rejection as final. Read the authoritative ledger result and inspect the bounded response artifact before reporting status, exit code, output, or files.
```

Instructions guide agent behavior; the installer's private-repository checks, OS identities, IPC authentication, and filesystem policy remain the enforcement boundary.

## ChatGPT

Use a ChatGPT Project or custom instructions for the reusable block, and connect only the dedicated private repository if the selected ChatGPT environment has a GitHub-capable connector. OpenAI documents project/personal instructions in [Personalize ChatGPT](https://learn.chatgpt.com/docs/personalize). Connector availability and permissions vary by account; if the environment cannot create issues and read Actions results, have it produce the validated request JSON for a separately authenticated narrow client instead of granting workstation credentials.

## Codex

Place the reusable block in the workload repository's root `AGENTS.md`, or in the nearest scoped `AGENTS.md` that governs remote execution. Codex loads root-to-current-directory instruction files and gives nearer files later precedence; see OpenAI's [Custom instructions with AGENTS.md](https://learn.chatgpt.com/docs/agent-configuration/agents-md).

Do not put private repository names, machine paths, or credentials in a public `AGENTS.md`. Keep operator-specific values in an untracked local override or the agent's private configuration.

## Claude Code

Place the reusable block in a private/local `CLAUDE.local.md`, or in `CLAUDE.md` when the repository itself is private and the values are safe to share with all readers. Claude Code reads `CLAUDE.md`, not `AGENTS.md`; its documented `@AGENTS.md` import can reuse non-sensitive shared project guidance. See [How Claude remembers your project](https://code.claude.com/docs/en/memory).

## Other GitHub-capable agents

Use the same request contract and least-privilege repository scope. The agent needs issue creation, repository content read, and Actions result/artifact read for the dedicated private repository. It does not need workflow write, repository administration, runner administration, or any credential from the workstation. If the integration cannot preserve those distinctions, use a separate narrow issue-submission client rather than broadening AWG's boundary.
