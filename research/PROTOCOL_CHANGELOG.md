# Protocol change log

## 2026-09-06 — v1.2 model migration

The v1.1 Groq model IDs (`llama-3.1-8b-instant` and
`llama-3.3-70b-versatile`) were no longer available from the configured
provider during the pre-collection check. A 49-call attempt against the v1.1
target was retained as a private failed-artifact record; it produced no usable
model responses and is not evidence.

Protocol v1.2 therefore uses the provider-advertised
`openai/gpt-oss-20b` target/weak judge and `openai/gpt-oss-120b` reference/strong
judge. The attack library, prompt version, labeling guide, temperatures,
token budgets, repeat count, and human-label assignment are unchanged. This is
a new corpus version: no v1.1 response, judge row, or label may be reused in
the v1.2 analysis.

The model-list check establishes that the IDs are advertised, not that a full
study run will succeed. Collection must still record provider failures and
remain subject to the publication gate.
