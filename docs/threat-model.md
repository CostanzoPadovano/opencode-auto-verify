# Threat model

## Scope

The system protects local project data during an agentic OpenCode session, especially when auto-approval is desired for routine work. The primary failure is an authorized agent issuing an effect that is broader or more destructive than the user's actual request.

## Assets

- Project source, notebooks, scientific data, analysis outputs, and local history.
- Explicit exclusions, keep-lists, protected paths, and other persistent user constraints.
- Reviewer credentials and conversation content.
- The integrity and recoverability of quarantine records.

## Trust boundaries

1. The user-agent conversation is an intent source, not an executable specification.
2. The agent-generated tool call is untrusted until its effects are classified.
3. The semantic reviewer is independent in role but may use the same underlying model and therefore may share failure modes.
4. OpenCode permissions and operating-system access control are outside the plugin and should remain active.
5. The local filesystem may change between preview and commit.

## Failure and abuse cases

| Case | Primary control | Residual risk |
| --- | --- | --- |
| Agent forgets an early exclusion | Constraint-preserving transcript selection, global policy, semantic review | Heuristic language matching can miss an unusual constraint |
| Agent constructs recursive or wildcard removal | Deterministic block plus native permission deny | Novel encodings or tools may evade a regex family |
| Agent retries the same denied effect through another interpreter | Global non-circumvention rule, unknown-tool review | A compromised or noncompliant agent may ignore prose policy |
| Reviewer over-trusts assistant narration | Authority labels; only user text can grant permission | Model may still violate the reviewer prompt |
| Reviewer endpoint fails or returns malformed output | Fail-closed verdict parser | Availability loss can block legitimate reviewed work |
| Arbitrary preview is treated as authorization | Commit performs a fresh user-scope review | Reviewer false allow remains possible |
| Source changes after preview | Session-bound expiry and filesystem identity recheck | Deep same-size content mutation may not change root identity |
| Quarantine is on another volume | Device check and no copy/delete fallback | Users must provision same-volume storage |
| Quarantine itself is lost | Separate protected root and manifest | Quarantine is not a backup; disk failure affects both |
| Sensitive context reaches a remote reviewer | Operator-controlled endpoint and key configuration | No comprehensive redaction or DLP layer is provided |

## Security invariants

- Broad permanent deletion is never delegated to semantic judgment.
- A generic “continue” cannot expand the authorized effect set.
- Assistant prose cannot grant authority.
- A protected project remains writable for exact authorized work but cannot be removed as a whole.
- Quarantine preview never mutates data.
- Quarantine commit cannot change target, cross session, outlive its token, or silently become copy-and-delete.
- A denial applies to the effect, not merely the spelling of the command.

## Non-goals

- Preventing a malicious user from deleting their own data.
- Sandboxing arbitrary code or defending against operating-system compromise.
- Guaranteeing scientific correctness or preventing every model hallucination.
- Replacing source control, immutable snapshots, offline backups, or incident response.
- Proving semantic equivalence across shells and programming languages.

## Recommended deployment

Use a dedicated low-privilege account, narrowly configured writable roots, same-volume quarantine outside active project roots, native denial patterns, private reviewer networking, version control, periodic snapshots, and a tested restore procedure. Treat expanded allow rules as security changes and test both false allows and false denials.
