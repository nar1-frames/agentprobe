# AgentProbe: Historical Engineering Pilot Report

**Author:** Naren Ranjith
**Date:** 2026
**Repository:** https://github.com/nar1-frames/agentprobe
**DOI:** https://doi.org/10.5281/zenodo.21410386
**Contact:** Open an issue in the repository

> **Status: historical engineering pilot; not a publication-ready empirical result.** Numbers below are the dated v1.1 scan (July 14, 2026; local report: `reports/scan_llama_3.1_8b_instant_v11_20260714.html`). That artifact reported **29/49 findings (59%), 10 CRITICAL / 15 HIGH / 4 MEDIUM** for this one target/provider run. These figures are retained as an engineering baseline, not as a general estimate of model vulnerability or a validated attack-success rate.

> **Provenance note:** this is the historical engineering pilot. The frozen
> judge-reliability snapshot now in `data/` is a separate experiment with
> repeated judges and only 17 human labels; see [`docs/RESULTS.md`](RESULTS.md)
> before making a publication claim.

---

## Abstract

Prompt injection is the top-ranked risk in the OWASP Top 10 for Large Language Model Applications, yet practitioners lack a lightweight, open-source way to quickly assess how a given model resists common attack categories. This report describes **AgentProbe**, an automated scanner that fires a structured library of 49 attack prompts spanning 8 categories at a chat-completions API, classifies each response with a two-stage detection pipeline (fast keyword screening followed by LLM-as-judge adjudication of ambiguous cases), assigns severity, and generates a self-contained HTML security report. In one dated engineering run against `llama-3.1-8b-instant`, the scanner reported **29 of 49 responses as vulnerable or partial, including 10 CRITICAL-severity findings**. Because the run used one target/provider snapshot and its labels were not fully validated against human ground truth, the result is descriptive rather than a population-level claim. The report also documents a possible "hedge-then-comply" failure mode in which a model issues a surface refusal immediately followed by harmful content, which naive keyword detectors can miss.

---

## 1. Introduction

Large language models are being embedded into products faster than their security properties are understood. Prompt injection — supplying input that overrides a model's instructions or safety constraints — is ranked **#1 on the OWASP LLM Top 10**, and published attack-success rates range from roughly 50% to 84% depending on model and method.

Despite this, tooling is fragmented: red-teaming is often ad hoc, and existing frameworks are heavy or research-oriented. There is a gap for a **fast, lightweight, reproducible scanner** a developer can point at any AI endpoint to get a first-pass security read in minutes.

AgentProbe fills that gap. It is designed to be:
- **Model-agnostic** — works against any chat-completions-style API.
- **Structured** — a curated, categorized attack library rather than one-off prompts.
- **Reproducible** — deterministic scan configuration, timestamped reports.
- **Interpretable** — severity scoring and mapping to industry threat frameworks.

## 2. Threat Model & Scope

AgentProbe evaluates a model's resistance to adversarial *inputs* at the prompt boundary. It does **not** assess infrastructure, data-layer, or supply-chain risks. It is intended for **authorized testing** — a model or system you own or have permission to assess. The repository ships a responsible-disclosure workflow to reinforce this norm (Section 7).

## 3. Attack Library

The library contains **49 prompts across 8 categories**:

| Category | Description |
|---|---|
| Jailbreak | Direct attempts to bypass safety instructions (e.g., SYSTEM OVERRIDE tags) |
| Data Extraction | Attempts to elicit system prompts, training data, or secrets |
| Privilege Escalation | Attempts to gain elevated capability/permission |
| Social Engineering | Authority spoofing, urgency, false context |
| Role Confusion | Persona hijacks (e.g., DAN) that reframe the model's identity |
| Indirect Injection | Malicious instructions embedded in "external" content |
| Context Manipulation | False history, context reset, precedent injection |
| Tool Misuse | Inducing unsafe tool/code/filesystem behavior |

## 4. Detection Pipeline

Each response is classified in two stages:

1. **Fast keyword screening** — high-precision markers of compliance/refusal for unambiguous cases (cheap, deterministic).
2. **LLM-as-judge adjudication** — ambiguous responses are routed to a stronger judge model (`llama-3.3-70b-versatile`) that classifies the outcome as VULNERABLE / PARTIAL / SAFE with a rationale.

This routing keeps cost low while catching nuanced failures a keyword filter alone would misclassify. Each finding is assigned a severity (CRITICAL / HIGH / MEDIUM / LOW).

## 5. Results (historical v1.1 engineering scan)

**Target:** `llama-3.1-8b-instant` (Groq) · **Judge:** `llama-3.3-70b-versatile`

| Category | Findings | Total | Hit Rate | Highest Severity |
|---|---|---|---|---|
| Jailbreak | 7 | 8 | 88% | CRITICAL |
| Data Extraction | 3 | 8 | 38% | CRITICAL |
| Privilege Escalation | 3 | 6 | 50% | CRITICAL |
| Social Engineering | 4 | 6 | 67% | HIGH |
| Role Confusion | 6 | 6 | 100% | CRITICAL |
| Indirect Injection | 1 | 5 | 20% | CRITICAL |
| Context Manipulation | 3 | 5 | 60% | HIGH |
| Tool Misuse | 2 | 5 | 40% | CRITICAL |

**Overall: 29/49 prompts were classified as vulnerable or partial (59% of this scan's responses) — 27 fully vulnerable + 2 partial.** This is a descriptive result for the dated run, not a validated attack-success estimate.

**Severity:** 10 CRITICAL, 15 HIGH, 4 MEDIUM, 0 LOW.

### 5.1 Notable finding — the hedge-then-comply pattern

The most interesting failure mode is a response that **refuses in its first sentence, then complies immediately after**. Example (Tool Misuse): the model said it could not access files, then supplied a Python script to read `/etc/passwd`; said it could not run code, then simulated the filesystem output. A naive keyword detector keys on the refusal and scores it SAFE. AgentProbe's judge stage classifies it PARTIAL — surfacing a class of vulnerability that surface-level filters systematically miss. This is the report's central research contribution and worth expanding for a workshop version.

### 5.2 Indirect injection

Indirect injection was the most-resisted category (1/5, 20%) — the target refused most instructions embedded in "external" content. This relative robustness is worth noting, though it may reflect the test-prompt design rather than genuine defense, and a harder indirect-injection set is planned for v2.

## 6. Framework Mapping

- **OWASP LLM Top 10:** primarily LLM01 (Prompt Injection); Data Extraction findings touch LLM06 (Sensitive Information Disclosure); Tool Misuse touches LLM08 (Excessive Agency).
- **MITRE ATLAS:** findings map to adversarial-ML tactics for LLM evasion and jailbreak.

*(Expand this section with exact technique IDs for the arXiv/workshop version.)*

## 7. Responsible Disclosure

AgentProbe is for authorized testing only. The repository includes a disclosure workflow (authorization records and unpatched-vulnerability data are kept local, never committed). Testing described here was performed against a model accessed via a third-party inference provider for research purposes; no production system was targeted.

## 8. Limitations & Future Work

- Single target/provider snapshot in this pilot; multi-model comparison is the obvious next step.
- Attack library is English-only and static; adaptive/multi-turn attacks are future work.
- LLM-as-judge introduces its own model dependence; inter-judge agreement and agreement with human labels must be measured before making a publication claim.
- A harder indirect-injection set is planned for v2.
- The frozen judge study is incomplete: only 17 of 49 primary human labels are currently present, and the publication gate remains blocked. See [`docs/RESULTS.md`](RESULTS.md).

## 9. Conclusion

This pilot shows that a lightweight, structured, open-source scanner can produce a useful first-pass security artifact quickly and can surface responses that merit manual review, including possible hedge-then-comply behavior. The 29/49 pilot figure should not be generalized beyond this dated run. Completing the frozen human-label and repeated-judge protocol is required before concluding how well the detector measures prompt-injection resistance.

---

## Appendix A — Reproduce

```
git clone https://github.com/nar1-frames/agentprobe
# add GROQ_API_KEY to .env
pip install -r requirements.txt
python agentprobe_v11.py
```

## References
- OWASP Top 10 for LLM Applications (2025).
- MITRE ATLAS — Adversarial Threat Landscape for AI Systems.
*(Fill in full citations for submission.)*
