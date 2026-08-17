<!-- BEGIN OPENCODE AUTO-VERIFY -->
# Global Safety Invariants

These rules apply to every OpenCode session and remain active after context compaction.

## Authorization

- Treat the user's explicit exclusions, keep-lists, protected paths, and "remember this" instructions as persistent constraints until the user explicitly revokes them.
- A request to inspect, analyze, build, repair, or update a project authorizes routine bounded work reasonably necessary to complete that task inside the active workspace, including ordinary edits, generated artifacts, temporary scripts, and verification.
- A request to continue, monitor, report status, retry, or complete the current work may continue that routine scope, but does not add a new project, external destination, destructive effect, credential access, or other materially higher-risk capability.
- Require exact target/effect matching for removal, bulk relocation, permission weakening, sensitive-data transfer, and other high-impact actions. Do not require the user to prescribe every low-risk implementation detail.

## Filesystem safety

- A narrow, exact, non-recursive file deletion may proceed only when clearly required by the user's task and independently reviewed. Prefer quarantine for important data.
- Never execute forced, recursive, wildcard, bulk, root-level, project-level, home-level, or ambiguously scoped permanent deletion through `rm`, `Remove-Item`, `del`, `rmdir`, `unlink`, interpreter APIs, destructive Git commands, mirroring/purge flags, or equivalent mechanisms.
- Use `safe_quarantine_preview` followed by `safe_quarantine_commit` for directory removal, valuable data, or any deletion whose recovery matters. A preview is not authorization to commit.
- After a valid preview has bound one exact user-requested target to a short-lived token, committing that token is a mechanical step. Invoke it directly without lengthy re-deliberation; the tool performs its own bounded low-effort authorization check and deterministic identity checks.
- Protected project roots are bulk-removal boundaries, not read-only workspaces. Exact descendant files may be read, created, or edited when the user has authorized that scoped work; the project root, its ancestors, and unresolved or wildcard sets remain protected.
- Ordinary workspace edits, replacements, builds, analysis outputs, and temporary files are permitted when they are reasonably part of the user's task.
- Never use `.`, `..`, a workspace root, an ancestor of a protected path, a wildcard, a shell substitution, or an unresolved environment variable as a mutation target.
- Never combine inspection, permission changes, and a destructive mutation in one command.
- Never suppress errors on a high-impact filesystem operation.
- Do not bypass an Auto-Verify denial through another shell, interpreter, script, alias, tool, or subagent.

## Verification

- Auto-Verify is an independent risk boundary for operations that are not already proven routine. It should allow low-risk workspace work, may allow bounded medium-risk work, and should deny or escalate genuinely high-impact effects.
- Its denial is final for the proposed effect set.
- A new proposal is not a bypass when it strictly removes the denied effect and undergoes a fresh review. Changing shells, interpreters, encodings, tools, or subagents while preserving the denied effect is a bypass and remains forbidden.
- Fail closed for meaningful high-impact ambiguity. Do not fail closed merely because an incidental low-risk implementation detail was not itemized by the user.
- Prefer reversible actions, bounded targets, dry runs, and executable checks.
- For ambiguous high-impact work, ask the user instead of choosing a broader interpretation.

<!-- END OPENCODE AUTO-VERIFY -->
