# Architecture

## Safety claim

Auto-Verify narrows the gap between conversational intent and executable effect. It does not attempt to prove that an agent is correct. Its narrower claim is that common catastrophic filesystem operations are either deterministically blocked or transformed into a bounded, reviewable, reversible operation, while routine workspace work remains usable.

```mermaid
flowchart TD
    A["Agent proposes a tool call"] --> B["Deterministic effect classifier"]
    B -->|"proven routine"| C["Execute"]
    B -->|"known catastrophic pattern"| D["Deny"]
    B -->|"bounded or uncertain"| E["Semantic authorization reviewer"]
    E -->|"authorization and exact scope proven"| C
    E -->|"ambiguous, conflicting, or broader"| D
    A -->|"removal should be recoverable"| F["Quarantine preview"]
    F --> G["Resolve path, inventory, identity, token"]
    G --> H["Quarantine commit review"]
    H -->|"authorized and unchanged"| I["Same-volume atomic rename"]
    H -->|"denied, expired, changed, or cross-device"| D
    I --> J["Manifest and recovery path"]
```

## Deterministic classification

`auto-verify-core.mjs` assigns each tool call one of three outcomes:

- `allow`: known read-only operations and exact edits below configured routine writable roots.
- `review`: effects that may be legitimate but require conversational scope reconstruction, including exact deletion, movement, package changes, and unknown tools.
- `block`: known broad or irreversible destructive families, including recursive removal, wildcard deletion, destructive Git cleanup, and purge-style synchronization.

The classifier is intentionally conservative about claims of safety. An unrecognized tool is reviewed rather than silently allowed. Routine `git add` is accepted only as one complete simple command; Git diff-producing forms are reviewed because repository or user configuration can attach helpers and output effects, and broad worktree-reset spellings are blocked even when global options such as `-C` or a nested shell command are present. GNU `find` actions that write to a named output file are reviewed, and Windows-mounted WSL path boundaries are compared case-insensitively. `nvidia-smi` is auto-allowed only for an explicit subset of status and query arguments; controls, file output, subcommands, and unknown flags are reviewed.

The implementation tokenizes security-sensitive Git command shapes but is not a complete shell parser, so native permission denials remain an independent layer.

## Semantic authorization review

The reviewer receives:

- Visible user and assistant messages as structured `{role, authority, text}` records.
- The exact tool name and sanitized arguments.
- The deterministic classification.
- Resolved effects when the quarantine tool has already bound them.
- Working, writable, protected, and quarantine roots.

User text can authorize. Assistant text can explain what a later “yes” refers to but cannot create permission, including through quoted or embedded role-like markers. Hidden reasoning is never forwarded. A verdict permits execution only when all of these are true:

- `decision` is `allow`.
- `risk_level` is `low` or `medium`.
- `user_authorized` is true.
- `scope_match` is true.
- `protected_conflict` is false.
- `violations` is a valid array of nonempty strings and is empty.

Reviewer requests use a strict JSON Schema by default. The local parser independently validates the same required fields, rejects wrappers and unexpected properties, and never interprets a missing field as positive evidence. When the first response is structurally invalid, the reviewer receives exactly one low-effort repair request containing the schema errors and a bounded copy of previously valid fields. A repair may complete a legitimate allow only if the first payload was a parseable object and contained no negative authorization fields. It cannot reverse a prior deny, high or critical risk, explicit authorization failure, scope failure, protected conflict, or nonempty violation set; an unparseable response likewise cannot be repaired into permission. A second malformed response fails closed. Schema-valid denials are never retried.

Unavailable, timed-out, incompatible, or non-JSON endpoints also fail closed for calls that reached review. Operators may select `json_object` or `off` only for endpoint compatibility; doing so does not relax local schema validation.

## Transcript compaction

When the visible transcript exceeds the review budget, the selector retains user messages that look like persistent constraints—such as exclusions, keep-lists, “never,” “remember,” and equivalent Italian forms—then fills the remaining budget from the newest conversation entries. This reduces one known failure mode but is heuristic. Critical invariants should also live in the managed `AGENTS.md` policy and deterministic configuration.

## Managed quarantine

Preview performs no mutation. It resolves a single path, rejects wildcards and substitutions, checks allowed and protected boundaries, records a bounded inventory and filesystem identity, and issues a session-bound token with a short expiry.

Commit re-resolves the source, checks the token, session, expiry, and source identity, asks a narrowly configured reviewer to validate user authorization, and then checks identity and inventory again. It verifies that source and quarantine share a filesystem device, creates real non-symlink `items`, container, and payload directories, rechecks destination containment, then uses `rename`. It never falls back to copy-and-delete. A separate manifest records the original path and reviewer result.

The repeated identity and inventory checks reduce time-of-check/time-of-use risk but are not a cryptographic snapshot of every byte below a directory. A narrow race between the final check and `rename` remains a documented platform-level residual risk.

## Installation boundary

The installer modifies only three targets inside the chosen OpenCode configuration directory:

- `plugins/auto-verify-guardian.js`
- `plugins/auto-verify-core.mjs`
- `plugins/quarantine-fs.mjs`
- The marker-bounded block in `AGENTS.md`

Existing targets receive timestamped backups. The installer does not rewrite the user's main JSONC configuration because safely merging arbitrary comments, ordering, and local rules requires user judgment. The uninstaller is recoverable and never deletes quarantine data.
