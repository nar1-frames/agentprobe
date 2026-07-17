# AgentProbe: A Lightweight Open-Source Scanner for Prompt-Injection Resistance in LLMs

**Author:** Naren Ranjith
**Date:** 2026
**Repository:** https://github.com/nar1-frames/agentprobe
**Contact:** [add email]

> **DRAFT for publication (Zenodo / arXiv-cs.CR / workshop).** Numbers below are the canonical v1.1 scan (July 14, 2026; report: `reports/scan_llama_3.1_8b_instant_v11_20260714.html`). All external mentions (resume, activities, blog) have been reconciled to these figures: **29/49 findings (59% ASR), 10 CRITICAL / 15 HIGH / 4 MEDIUM.**

---

## Abstract

Prompt injection is the top-ranked risk in the OWASP Top 10 for Large Language Model Applications, yet practitioners lack a lightweight, open-source way to quickly assess how a given model resists common attack categories. We present **AgentProbe**, an automated scanner that fires a structured library of 49 attack prompts spanning 8 categories at any chat-completions API, classifies each response with a two-stage detection pipeline (fast keyword screening followed by LLM-as-judge adjudication of ambiguous cases), assigns severity, and generates a self-contained HTML security report. Run against `llama-3.1-8b-instant`, AgentProbe found that **29 of 49 attacks (59%) produced vulnerable behavior, including 10 CRITICAL-severity findings**. Findings are mapped to the OWASP LLM Top 10 and the MITRE ATLAS adversarial-ML matrix. We discuss a notable "hedge-then-comply" failure mode in which a model issues a surface refusal immediately followed by harmful content, which naive keyword detectors miss.

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

## 5. Results (v1.0 scan)

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

**Overall: 29/49 prompts produced vulnerable behavior (59% attack success rate) — 27 fully vulnerable + 2 partial.**

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

- Single target model in v1.0; multi-model comparison is the obvious next step.
- Attack library is English-only and static; adaptive/multi-turn attacks are future work.
- LLM-as-judge introduces its own model dependence; inter-judge agreement should be measured.
- A harder indirect-injection set is planned for v2.

## 9. Conclusion

AgentProbe demonstrates that a lightweight, structured, open-source scanner can surface serious prompt-injection vulnerabilities — a 59% attack-success rate with 10 CRITICAL findings on a widely used model — in minutes, and can catch nuanced failure modes (hedge-then-comply) that naive detectors miss. The tool lowers the barrier to first-pass LLM security assessment for developers who are not security specialists.

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
