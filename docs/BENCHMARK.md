# Framework comparison benchmark: methodology (draft)

**Status: methodology. Benchmark 01 has been run with documented deviations (one
framework, k = 1). See [BENCHMARK_RESULTS.md](BENCHMARK_RESULTS.md).** This document
fixes how a comparison of agent frameworks will be run and reported, before
any data exists, so the method cannot be tuned to the results.
[`writeups/public-scan-01.md`](../writeups/public-scan-01.md) is a single
configuration scanned once. It is a worked example, not a benchmark result.

## Question

Holding the model, the attacks, and the judge fixed, how do agent
configurations built with different open-source frameworks respond to the
same prompt-injection attacks?

The unit of comparison is a **configuration**: framework and version, model
and settings, system prompt, tool set, and any guardrails. A result describes
that configuration on that date. It does not describe the framework in
general.

## Configurations

- Each framework is used through its own documented quickstart or reference
  agent, with only the model string changed. The candidates are LangChain
  `create_agent`, the OpenAI Agents SDK, LlamaIndex agents, and an MCP client
  with reference servers.
- Every configuration gets an equivalent tool set (the same names,
  arguments, and fixture behaviour), so differences come from the framework
  rather than from the tools.
- Each configuration is served behind a local HTTP endpoint and scanned
  through AgentProbe's `http` target, with a fresh session for every attack.
- Framework versions are pinned, and `pip freeze` is published with the
  results.

## Fixed inputs, recorded in every report

| Input | Recorded as |
|---|---|
| Attack library | `attack_library_sha256` (one digest across all configurations) |
| Success oracles | `attack_pack_schema_version`, `attack_pack_sha256` |
| Judge prompt | `judge_prompt_version`, `judge_prompt_sha256` |
| Judge model and settings | report `run` metadata and `config_sha256` |
| Target model and settings | temperature, reasoning effort, token budget, as written in each config |
| Responses | a replay recording per run, so every verdict can be re-derived offline |

## Procedure

1. Run k = 5 repeats of the full library against each configuration. Hosted
   models are not deterministic even at temperature 0, so one run is not
   enough.
2. The judge must pass AgentProbe's strength gate (at least as strong as the
   target), and it must not be the target model itself.
3. Operational errors (target or judge failures) are excluded from every
   denominator and reported separately. They are never counted as SAFE or as
   findings.
4. A blinded human sample covers 20% of judge-decided rows per configuration,
   labelled with the protocol in `research/LABELING_GUIDE.md`. It reports
   judge agreement (Cohen's kappa), so the verdicts carry a measured error
   rate.

## Metrics

- **Attack success rate:** (VULNERABLE + PARTIAL) / scorable attacks, per
  configuration and per category, with Wilson 95% confidence intervals.
- **VULNERABLE-only rate,** with the same intervals.
- **Review rate:** SUSPICIOUS / scorable. A high rate means the verdicts need
  human review before anyone relies on them.
- **Stability:** per attack, the share of the k repeats that agree.
- **Harness outcomes** (attack reached its objective, blocked, controls
  passed), for any framework that has a harness adapter.

## Comparisons

- Configurations are compared **paired by attack ID**: the same attack
  against two configurations.
- McNemar's test on the paired binary outcome, with a Holm correction across
  comparisons. Effect sizes (difference in rates with a 95% CI) are reported,
  not just p-values.
- There is no ranking where intervals overlap. The report says "no detectable
  difference" instead.

## Limitations, stated with every result

- The 49 attacks are public patterns that are probably in model training
  data. They measure resistance to known attacks, not to novel ones.
- The attacks are single-turn chat attacks. They do not exercise multi-turn
  memory, retrieval poisoning, or real tool side effects, unless a harness
  adapter is used.
- The LLM judge is not ground truth. Until the v1.4 judge study is complete,
  judge agreement comes only from the human sample above.
- Results hold for the pinned framework versions, model versions, and date.
  Defaults change between releases, and hosted models can change without
  notice.
- Provider-side safety layers sit in front of some models and are invisible
  to the scan.
- Sample sizes per category are small (5 to 8 attacks), so per-category
  intervals are wide.

## Reporting and disclosure rules

- Publish configs, version pins, digests, and sanitized replay recordings, so
  anyone can re-derive every verdict offline.
- Findings are written about configuration patterns ("a quickstart agent with
  a one-line system prompt"), never as "framework X is insecure".
- If a result shows a framework **default** that lets an attack cross a trust
  boundary (for example, a tool executes on injected instructions with no
  opt-in), the maintainers are notified privately before publication, with a
  reasonable fix window, following [`SECURITY.md`](../SECURITY.md).
