# OpenCode Auto-Verify

OpenCode Auto-Verify is an experimental, risk-tiered guardian for agentic coding sessions. It lets ordinary work continue automatically, sends ambiguous or consequential actions to an independent semantic reviewer, blocks broad permanent deletion, and provides a reversible quarantine for intentional removal.

The project began after a real agentic-session failure: an assistant lost an earlier keep-list constraint and executed a broad, forced removal against a project tree. The incident showed that conversational memory, model quality, and quantization are not sufficient safety boundaries. An agent can reason well and still act on an incomplete reconstruction of user intent. Auto-Verify therefore evaluates the proposed effect at tool-execution time, when the exact command and target are known.

This is an unofficial community project by Costanzo Padovano. It is not affiliated with or endorsed by OpenCode, OpenAI, Qwen, or Alibaba Cloud.

## Design

The guardian combines four layers:

1. A deterministic classifier allows known read-only commands and routine edits within configured workspace roots.
2. Broad, forced, recursive, wildcard, project-level, and similarly destructive permanent-removal patterns are blocked before execution.
3. Bounded but uncertain actions are judged against the visible conversation by an OpenAI-compatible reviewer model. Only user messages can grant authority; assistant messages are context, never permission.
4. Important removal is represented as a same-volume rename into a managed quarantine. Preview and commit are separate, short-lived, identity-bound operations.

The design intentionally resembles human re-reading before a consequential action, but it is not a claim of equivalence with any proprietary approval system. See [Architecture](docs/architecture.md) and [Threat model](docs/threat-model.md).

## What it permits

- Read-only inspection and ordinary verification.
- Exact file creation and edits below configured routine writable roots.
- Normal temporary scripts in configured temporary roots.
- Git staging and other actions proven routine by the deterministic classifier.
- Bounded medium-risk actions when the reviewer can prove user authorization and scope match.

## What it stops or redirects

- Forced, recursive, wildcard, bulk, root-level, project-level, or home-level permanent deletion.
- Destructive Git cleanup and worktree reset patterns.
- Mirroring or synchronization modes that delete destination content.
- Ambiguous high-impact actions and actions that conflict with a persistent exclusion or protected root.
- Attempts to preserve a denied effect by changing shell, interpreter, encoding, tool, or sub-agent.

Protected roots are removal boundaries, not read-only workspaces. Exact descendant files remain editable when the task authorizes the change.

## Requirements

- OpenCode with JavaScript plugin support.
- Node.js 20 or newer for installation and tests.
- Linux or WSL2 for the current quarantine implementation.
- An OpenAI-compatible `/chat/completions` endpoint for semantic review.
- A quarantine directory on the same filesystem volume as the protected workspace. Cross-device moves are denied because copying and deleting would weaken atomicity and recoverability.

## Quick start

Clone the repository, then configure absolute paths in a private environment file. The built-in `/workspace` and `/quarantine` defaults are inert examples, not production recommendations.

```bash
cp examples/server.env.example ~/.config/opencode/auto-verify.env
$EDITOR ~/.config/opencode/auto-verify.env
set -a
. ~/.config/opencode/auto-verify.env
set +a
```

Preview the installation:

```bash
node scripts/install.mjs ~/.config/opencode
```

Apply it:

```bash
node scripts/install.mjs ~/.config/opencode --apply
```

The installer copies the plugin and its two support modules, preserves timestamped backups, and manages only the marked Auto-Verify block in `AGENTS.md`. It deliberately does not rewrite arbitrary OpenCode JSONC. Merge [the permission example](examples/opencode.permissions.jsonc) into your own configuration, keeping native denial rules as defense in depth.

Restart OpenCode after installation or configuration changes. The reviewer server does not need to be restarted when only the OpenCode plugin or `AGENTS.md` changes.

To disable the plugin recoverably:

```bash
node scripts/uninstall.mjs ~/.config/opencode
node scripts/uninstall.mjs ~/.config/opencode --apply
```

The uninstaller renames installed modules, backs up and removes only the managed policy block, and never touches quarantine contents.

## Configuration

Path lists are separated by semicolons.

| Variable | Purpose | Default |
| --- | --- | --- |
| `OPENCODE_QUARANTINE_ALLOWED_ROOTS` | Roots from which quarantine moves may originate | `/workspace` |
| `OPENCODE_AUTO_VERIFY_WRITABLE_ROOTS` | Roots where routine edit tools may proceed without semantic review | `/workspace;/tmp/opencode` |
| `OPENCODE_PROTECTED_PATHS` | Roots protected against bulk removal, relocation, and ancestor mutation | `/workspace;/quarantine` |
| `OPENCODE_QUARANTINE_ROOT` | Managed quarantine destination | `/quarantine` |
| `OPENCODE_AUTO_VERIFY_BASE_URL` | OpenAI-compatible API base URL | WSL gateway on port `8030` |
| `OPENCODE_AUTO_VERIFY_MODEL` | Reviewer model identifier | Current session model when discoverable |
| `OPENCODE_AUTO_VERIFY_PROVIDER` | Provider label retained for integration compatibility | `llama_router` |
| `LLAMA_ROUTER_API_KEY` | Optional API key supplied directly | unset |
| `LLAMA_ROUTER_KEY_FILE` | Optional file containing the API key | unset |
| `OPENCODE_AUTO_VERIFY_TIMEOUT_MS` | General review timeout | `180000` |
| `OPENCODE_AUTO_VERIFY_REASONING_EFFORT` | General semantic-review effort | `xhigh` |
| `OPENCODE_AUTO_VERIFY_MAX_TOKENS` | General review output budget | `8192` |
| `OPENCODE_AUTO_VERIFY_RESPONSE_FORMAT` | Reviewer output constraint: `json_schema`, `json_object`, or `off` | `json_schema` |
| `OPENCODE_AUTO_VERIFY_SCHEMA_REPAIR_REASONING_EFFORT` | Effort for the single schema-repair attempt | `low` |
| `OPENCODE_AUTO_VERIFY_SCHEMA_REPAIR_MAX_TOKENS` | Output budget for the single schema-repair attempt | `1024` |
| `OPENCODE_QUARANTINE_REVIEW_REASONING_EFFORT` | Narrow quarantine-commit review effort | `low` |
| `OPENCODE_QUARANTINE_REVIEW_MAX_TOKENS` | Narrow quarantine-commit output budget | `2048` |
| `OPENCODE_QUARANTINE_PREVIEW_TTL_MS` | Lifetime of a preview token | `600000` |
| `OPENCODE_QUARANTINE_SCAN_LIMIT` | Maximum entries counted during preview | `20000` |

General review defaults to `xhigh` because scope reconstruction and conflicting constraints are the difficult part. Quarantine commit uses `low` by default because the preview has already resolved one exact target; the second review still prevents an arbitrary preview from becoming authorization.

The default reviewer request uses a strict JSON Schema. If a provider ignores the constraint and returns malformed output, Auto-Verify makes exactly one low-effort schema-repair request. It never fills a missing field locally, never retries a schema-valid denial, and never permits the repair to reverse negative evidence from the first response. A repaired allow is possible only when the first payload was a parseable object with no negative authorization fields; prose, invalid JSON, and wrappers remain fail-closed even if the retry says allow. A second malformed response also fails closed. `json_object` and `off` are compatibility modes for endpoints without JSON-Schema support; the same parser and one-retry boundary still apply.

## Validation

Run the deterministic test suite:

```bash
npm test
```

If a reviewer endpoint is running, exercise a live scenario:

```bash
set -a; . ./examples/server.env.example; set +a
node test/reviewer-live-smoke.mjs deny
node test/reviewer-live-smoke.mjs allow
node test/reviewer-live-smoke.mjs protected_write
```

Live reviewer behavior is model-dependent. A passing smoke test is evidence for the tested model, template, endpoint, and configuration—not a universal guarantee.

## Security posture

Auto-Verify is defense in depth, not an operating-system sandbox, backup system, or proof of alignment. Keep version control, snapshots, and tested backups. Retain native OpenCode permission denials for destructive primitives. Do not expose the reviewer endpoint or API key unnecessarily. Review the [security policy](SECURITY.md), [threat model](docs/threat-model.md), and anonymized [incident case study](docs/incident-case-study.md) before deployment.

## Attribution and license

Copyright 2026 Costanzo Padovano. Released under the Apache License 2.0. If you build on this work, retain the license and NOTICE and cite the project using [CITATION.cff](CITATION.cff).
