# Case study template (anonymized)

Use this only with the client's written consent. Ask for it at close-out (see
docs/ASSESSMENT.md section 10), and agree the level of anonymity before you
write a word. Keep it to one page: buyers skim.

---

## [Industry] company secures its customer-facing AI agent before [launch / enterprise rollout]

**At a glance**

| | |
|---|---|
| Company | [A Series A fintech, a 40-person support-automation startup, ...]. No name unless approved in writing |
| System | [Customer support agent with two tools: order lookup and email] |
| Engagement | Fixed-fee AgentProbe assessment, [month year], with one retest |
| Result | [FAIL, score 40] at first test → [PASS, score 92] at retest |

### Context

Two or three sentences. Why they needed an assessment now: an enterprise
security questionnaire, a launch date, an incident elsewhere in the
industry. Use the client's words if they gave them.

### Scope

- [One agent reachable over HTTP (staging), two tools]
- [49 attacks from the AgentProbe library, plus the harness policy review of
  both tools]
- [What was explicitly out of scope]

### Findings by OWASP LLM Top 10 (2025) category

| OWASP category | Findings | Most severe | What it looked like (paraphrased, no client text) |
|---|---|---|---|
| LLM07:2025 System Prompt Leakage | [2] | [HIGH] | [Asked politely, the agent summarized its instructions and tool list] |
| LLM01:2025 Prompt Injection | [1] | [CRITICAL] | [Text inside a quoted message overrode the task] |
| LLM06:2025 Excessive Agency | [0] | n/a | [The email tool was already restricted to the customer's own address] |

Include findings the analyst added (judge misses) and say how many judge
findings were set aside as false positives. Being honest about the method
is part of the pitch.

### Fixes

| Fix | Layer | Effort they reported |
|---|---|---|
| [Confidentiality clause in the system prompt] | Model (probabilistic) | [10 minutes] |
| [Recipient allowlist on the email tool] | Architecture (durable) | [half a day] |
| [Removed internal tool names from user-facing errors] | Application | [1 hour] |

### Retest delta

- **Score:** [40 → 92] (from the retest report's header).
- **Fixed:** [3]. **Still open:** [1], accepted risk because [reason].
  **New:** [0]. **Got worse:** [0].
- **Comparable:** same attack library and judge, both reviewed by the analyst.

### In their words

> "[Quote placeholder. Get approval for the exact wording.]"
> [Role, company type]. No name unless approved.

### About the assessment

Fixed fee, five business days, one retest included, built on the
open-source AgentProbe harness: [link to the offer or site].

---

## Anonymization checklist (complete before sending a draft to the client)

- [ ] **Written consent** to publish, including the agreed anonymity level
  (fully anonymous, industry only, or named). Keep the email.
- [ ] **No company, product, or person names** unless the consent says so.
  This includes repository names, domains, and model or deployment names
  that identify them.
- [ ] **No raw model responses or prompts** from their system. Paraphrase the
  behaviour; never paste the reply or their system prompt.
- [ ] **No identifying numbers:** exact headcount, funding round amount,
  customer counts, or launch dates that pin them down. Round or omit.
- [ ] **No endpoint, tool, or schema details** beyond generic descriptions
  ("an order-lookup tool").
- [ ] **No unfixed findings** described in a way that helps an attacker.
  Accepted risks are mentioned only by category.
- [ ] **Scores and deltas** match the delivered reports exactly.
- [ ] **The client has approved the final text,** including the quote,
  in writing.
- [ ] **Raw data deleted** per the SoW, and confirmed in writing before
  publication.
