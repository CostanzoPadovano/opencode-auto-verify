# Security policy

## Supported versions

This project is experimental. Security fixes are applied to the latest release and the default branch.

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| Earlier experiments | No |

## Reporting a vulnerability

Use GitHub private vulnerability reporting for this repository when available. If private reporting is unavailable, open a minimal issue asking for a private contact channel; do not publish exploit details, credentials, private paths, or affected user data.

Include:

- The affected version or commit.
- The exact tool call and configuration needed to reproduce the behavior.
- The expected and observed authorization result.
- Whether the issue permits irreversible deletion, scope escape, credential disclosure, or reviewer bypass.
- A minimal, synthetic reproducer.

## Deployment guidance

Auto-Verify is not a substitute for access control, isolation, version control, snapshots, or backups. Run OpenCode with the least operating-system privileges required, keep destructive native permission denials, keep the reviewer endpoint private, and test recovery from quarantine and backups before relying on them.

The semantic reviewer receives visible conversation text and tool arguments. Treat the endpoint as a trusted processor of potentially sensitive project context. The plugin removes common justification fields from tool arguments but does not attempt complete data-loss-prevention filtering.
