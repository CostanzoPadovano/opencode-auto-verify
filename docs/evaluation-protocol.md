# Evaluation protocol

Auto-Verify should be evaluated as a decision system, not by a handful of persuasive transcripts.

## Experimental unit

One trial contains a visible conversation, an exact proposed tool call, resolved execution context, and an expected verdict. Keep the filesystem synthetic. Record the model, weights or quantization, serving engine and commit, chat template, context size, reasoning setting, sampling parameters, seed, hardware, and latency.

## Scenario strata

- Routine true positives: ordinary reads, edits, temporary scripts, builds, and verification that should proceed.
- Bounded reviewed actions: exact movement, package changes, commits, and one-file deletion with explicit authorization.
- Persistent-constraint conflicts: early exclusions followed by long distracting conversations and generic “continue” messages.
- Catastrophic negatives: recursive, wildcard, root, ancestor, project, and home removal across shell and interpreter spellings.
- Quarantine lifecycle: preview, expired token, cross-session token, changed source, protected target, cross-device target, and valid commit.
- Friction recovery: permission errors and alternative safe paths without bypassing a denial.

## Metrics

- Catastrophic false-allow rate, reported separately and targeted at zero for deterministic families.
- Reviewed false-allow rate.
- Routine false-denial rate.
- Quarantine recovery success.
- Reviewer JSON-validity rate and endpoint failure rate.
- Median and tail authorization latency.
- Reviewer input and output tokens.

Report confidence intervals and raw trial counts. Repeat stochastic reviewer conditions across seeds. Paired tests are preferred when comparing reasoning levels or quantizations.

## Reasoning-effort study

Do not assume that more reasoning is uniformly better. Compare the endpoint's native named settings, such as `low`, `medium`, and `xhigh`, without imposing a fixed hidden-token budget unless the server requires one. First verify the rendered chat template: a named option that validates but renders no instruction is a different condition, not a true middle setting.

Use `xhigh` where the reviewer must reconstruct a long plan, resolve conflicting constraints, or verify an ambiguous effect. Use a lighter setting for a token-bound quarantine commit only after the exact path and operation are already resolved. Measure correctness and latency rather than selecting by intuition.

## Release gate

A release candidate should pass deterministic tests on every supported Node version, show no catastrophic false allows in the published synthetic battery, document all live-reviewer failures, and include an explicit recovery drill. Results from one model configuration must not be generalized to another without replication.
