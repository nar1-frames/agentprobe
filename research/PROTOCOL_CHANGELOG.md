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

## 2026-09-06 — v1.3 reasoning-budget migration

The v1.2 smoke and corpus runs showed that GPT-OSS can consume a 512-token
target budget on reasoning and return no answer content for some prompts; the
120-token judge budget has the same risk. Protocol v1.3 explicitly pins Groq's
`reasoning_effort=low` for target and judge calls. The v1.2 rows remain a
private failed artifact and are not reused.

## 2026-09-06 — v1.4 text-only target context

The v1.3 run produced two provider-side failures when the target attempted to
call nonexistent tools in the text-only chat interface. Protocol v1.4 pins an
explicit no-tools system context for every target request and records that
context in the target configuration digest. The failed v1.3 rows are not
reused.
