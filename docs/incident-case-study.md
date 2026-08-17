# Incident-driven case study

## Observation

During a long agentic coding session, the user had explicitly identified project content that had to remain in place. Later, after multiple turns and operational steps, the assistant proposed and executed a broad forced-removal command against a larger tree than intended. Auto-approval meant the command crossed from generated text to filesystem effect without a final independent scope check. Recovery required manual intervention and was much harder than it would have been with a managed recycle or quarantine layer.

Names, paths, data, and transcript details are intentionally anonymized. This document separates observed behavior from causal hypotheses.

## What the incident does establish

- The final command was materially broader and more destructive than the intended task.
- An earlier user constraint was not effectively enforced at execution time.
- Broad permanent deletion had been available to the agent under auto-approval.
- No equivalent of an external, recoverable recycle boundary intercepted the action.
- A later explanation or model self-critique could not undo the filesystem effect.

## What it does not establish

The incident alone does not identify quantization, key/value-cache precision, reasoning effort, context length, MTP, or a specific model defect as the cause. Those factors can change behavior, but attributing causality would require controlled repetitions with the same transcript, template, sampler, server, tool policy, and exact filesystem state. A single failure is evidence of system-level insufficiency, not a clean model comparison.

## Plausible contributing mechanisms

Several mechanisms can coexist:

1. Context reconstruction failure: the active response did not retrieve or prioritize the earlier exclusion.
2. Scope compression: a broad operational phrase was converted into a simpler but over-inclusive command.
3. Action bias under auto-approval: after deciding to “continue,” the agent optimized for completion rather than reopening the authorization boundary.
4. Weak tool boundary: the shell exposed permanent recursive removal as an ordinary executable primitive.
5. Missing recovery primitive: deletion was represented as erasure rather than a reversible state transition.

The important engineering conclusion is independent of which cognitive mechanism dominated: a safety-critical constraint should not rely on the same generative pass that proposes the action.

## Counterfactual controls

Under Auto-Verify, the observed command family is deterministically blocked. If the user genuinely wanted the directory removed, the agent would instead:

1. Request a quarantine preview for one exact target.
2. Receive its resolved path, bounded inventory, destination, expiry, and token.
3. Submit the token to a separate authorization review using the visible user request.
4. Move the unchanged target through a same-volume atomic rename.
5. Retain a manifest from which a human can restore it.

This does not make the reviewer infallible. It changes the failure geometry: an irreversible, high-blast-radius operation becomes a blocked class, while a legitimate removal becomes exact and recoverable.

## Lessons

- Model memory is useful evidence but not durable authorization state.
- Auto-approval should be risk-tiered, not an undifferentiated “yes to everything.”
- High-quality reasoning helps most at ambiguous plan and verification boundaries; deterministic rules should still own catastrophic effects.
- A second reviewer should evaluate the user's request and the resolved effect, not merely the agent's justification.
- Scientific evaluation should report false denials as well as prevented incidents; unusably restrictive safety produces workarounds.

## Status

The initial implementation and regression tests encode the incident's command family, persistent exclusions, protected-root semantics, semantic verdict requirements, and quarantine flow. Broader shell parsing, cryptographic directory snapshots, cross-platform recycle-bin adapters, and independent-model reviewer studies remain future work.
