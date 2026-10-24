# AI agent security assessment: design-partner offer

**Find out, in five business days, whether prompt injection can make your
agent leak its instructions, adopt an attacker's persona, or reach for a tool
it should not, and get the fixes ranked by where they actually hold.**

Prepared by Naren Ranjith, maintainer of
[AgentProbe](https://github.com/nar1-frames/agentprobe), the open-source
agent security harness this assessment runs on.

## Price

| | |
|---|---|
| **Design-partner price** | **$2,500, fixed fee, one retest included** |
| List price | $6,000 |
| Design-partner terms | Feedback after delivery, and optional permission to publish an anonymized case study. The fee does not depend on either |
| Payment | Set in the statement of work |

## What is in scope

- **One agent** reachable over HTTP (staging preferred), **with up to two
  tools**.
- **The AgentProbe attack library:** 49 public prompt-injection attacks in 8
  categories (jailbreak, data extraction, privilege escalation, social
  engineering, role confusion, indirect injection, context manipulation, tool
  misuse). Each is sent once, in its own conversation, through your agent's
  own API, so your system prompt, tools, retrieval, and guardrails are all in
  the loop.
- **Harness policy checks:**
  - a live harness run of your model and system prompt against AgentProbe's
    fixture tools (indirect injection, exfiltration, file-boundary,
    privilege, and network scenarios). This shows whether injected content
    makes the model *request* a harmful action. Your real tools are never
    called.
  - a policy review of your two tools against five controls: allowlist and
    per-call approval, path boundary, data-sink rule, network-destination
    rule, and call-depth limit.
- **Human triage:** every finding the automated judge reports is read by
  hand. False positives are set aside with a written reason, and they stay
  visible in the report. Every reply is also searched for your own prompt and
  tool text, and leaks the judge missed are added with a verbatim quote as
  evidence.
- **The report:** one self-contained HTML file plus a PDF.
  - A PASS / FAIL / INCOMPLETE result and a 0-100 score.
  - Findings ranked by severity, each with the response excerpt and the fix,
    split by layer (architecture fixes hold; model-layer fixes are
    probabilistic).
  - An OWASP Top 10 for LLM Applications (2025) mapping and a methodology
    appendix.
  - SARIF for your code-scanning tools.
  - See the [sample report](../examples/sample-report/sample-report.pdf).
- **A 30-minute delivery call.**
- **One retest within 30 days of delivery:** the same attacks against your
  fixed version, with the score change and a "Changes since baseline" section
  that lists what is fixed, new, regressed, or still open. See the
  [sample retest](../examples/sample-retest/sample-retest.pdf).

## What is out of scope

- Infrastructure, network, or web-application penetration testing.
- Agents beyond the first, tools beyond the second, and environments not
  named in the statement of work.
- Novel attack research, multi-turn or long-horizon attacks, and retrieval
  (RAG) poisoning. These are on the AgentProbe roadmap and can be scoped
  separately.
- Executing your real tools, or any testing of production data or accounts.
- Certification or any guarantee of safety. This is control testing of one
  configuration on the stated dates.

## Timeline: five business days

| Day | What happens |
|---|---|
| 0 | 30-minute scoping call; statement of work with authorization signed |
| 1 | Endpoint wired and smoke-tested against your staging environment |
| 2 | Scan, live harness, and policy review |
| 3 | Triage and report |
| 4 | Report delivered, 30-minute walkthrough |
| within 30 days | Retest and comparison report |

## What you provide

- A staging or test endpoint for the agent, and its request and response
  format.
- A revocable scan token for that endpoint, issued for this test only.
- For the live harness: OpenAI-compatible access to the underlying model and
  the system prompt. Without these the harness step is skipped, the report
  says so, and the price is unchanged.
- The two tool definitions (names, arguments, side effects).
- A technical contact during the test window.

## Authorization

No request is sent to your system until a signed statement of work names the
system, the environment, the test window, the expected request volume (about
50 requests per run), and the person authorizing the test. Testing stays
inside that scope.

Model responses collected during the test are kept only as long as the
statement of work allows, and are deleted afterwards with written
confirmation. You receive the report, PDF, and SARIF. Raw responses are
shared only if you ask for them.

## Next step

Reply to book a 30-minute scoping call: **Naren Ranjith, [CONTACT EMAIL]**.
