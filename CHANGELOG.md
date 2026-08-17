# Changelog

All notable changes to this project will be documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
