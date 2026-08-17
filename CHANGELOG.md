# Changelog

All notable changes to this project will be documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

- Restricted the routine `git add` fast path to one complete simple command so appended shell effects cannot inherit its allow verdict.
- Added conservative Git command-shape checks for global options, broad worktree targets, and external diff or text-conversion helpers.
- Replaced the broad `nvidia-smi` fallback with an explicit query-only allowlist; hardware controls and unknown forms now require review.
- Routed GNU `find` output-file actions through review instead of treating them as read-only, and made WSL Windows-mount boundaries case-insensitive.
- Refused symlinked components while creating a configured quarantine root, before any child directory can be created through the redirect.
- Added strict JSON-Schema-constrained reviewer output and one monotonic, fail-closed schema-repair attempt so an omitted field cannot silently authorize or unnecessarily terminate a legitimate reviewed action.
- Load an allowlisted private `auto-verify.env` directly so reviewer credentials survive restarts without hard-coded secrets or shell-profile coupling, and make HTTP authentication failures actionable.
- Treat each session's active OpenCode directory as a routine writable root so ordinary project creation and edits do not inherit the inert `/workspace` example default; destructive operations remain independently guarded.
- Auto-allow known low-impact inspection chains, including `ffprobe` and harmless shell pipelines, while retaining review for arbitrary interpreters, network access, mutation, and deletion.

## [0.1.0] - 2026-08-17

### Added

- Deterministic classification of read-only, routine, review-required, and blocked tool calls.
- Independent semantic authorization review using an OpenAI-compatible endpoint.
- Persistent treatment of explicit exclusions and protected roots during transcript compaction.
- Two-stage, same-volume managed quarantine with expiring tokens, source identity checks, and manifests.
- Structured reviewer transcripts, strict verdict-schema validation, and merged long-session constraint history.
- Symlink-resistant quarantine containers with a separate payload directory and post-review identity checks.
- Recoverable installer and uninstaller for OpenCode configuration directories.
- Unit tests, live reviewer smoke scenarios, threat model, and anonymized incident narrative.

[Unreleased]: https://github.com/CostanzoPadovano/opencode-auto-verify/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/CostanzoPadovano/opencode-auto-verify/releases/tag/v0.1.0
