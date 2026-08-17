# Contributing

Contributions are welcome. Safety-policy changes need evidence because both false allows and false denials matter.

## Development workflow

1. Create a focused branch.
2. Add or update a synthetic regression test for every classifier or authorization-policy change.
3. Run `npm run check` and `npm test`.
4. Describe the intended effect set, bypass cases considered, and user-experience trade-off in the pull request.

Do not include real project names, paths, prompts containing private data, API keys, or unredacted incident transcripts. Use synthetic fixtures.

## Policy principles

- Preserve ordinary authorized work; a safety layer that blocks all edits is not useful.
- Judge effects, not shell spelling.
- Keep permanent high-impact deletion deterministic and fail closed.
- Treat model review as fallible evidence, never as the sole protection for catastrophic operations.
- Prefer reversible, exact, previewable operations.
- Keep user messages authoritative and assistant messages contextual only.

Classifier expansions should include positive and negative controls. Reviewer experiments should report model, quantization, chat template, reasoning setting, context size, sampling parameters, endpoint version, repeated seeds, latency, false-allow rate, and false-denial rate.
