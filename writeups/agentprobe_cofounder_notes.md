# AgentProbe — Co-founder Notes

Review of the live repo (`nar1-frames/agentprobe`, v10 / "v1.0"). Three parts:
a real code review, the sharpened story + interview points, and a responsible
v1.1 plan.

---

## 1. Code review

### What's genuinely good

- **Data/logic separation is clean.** `attacks/library.py` is pure data; the
  scanner is pure logic. Every attack carries a `description` of *what it tests*.
  That single design choice is why the library reads like a security catalogue
  instead of a pile of strings.
- **The two-stage router is the right architecture.** Cheap keyword pass first,
  expensive LLM judge only when uncertain. That's exactly how you'd build this
  to control cost, and it's the part most worth talking about.
- **The judge prompt is well-built.** It asks for *behavior, not wording*, names
  the hedge-then-comply pattern explicitly, and pins an exact output format. Most
  people's first judge prompt does none of those.
- **Severity model is sensible.** Base severity from the attack, downgrade one
  level for PARTIAL. Easy to defend.

### Real issues (specific, ordered by impact)

**1. Your hedge-then-comply keyword detector never actually fires as a verdict.**
In `keyword_check`, a detected partial returns `("PARTIAL", 1, ...)`. But
`assess_vulnerability` only trusts the keyword stage when `kw_confidence >= 2`.
Confidence is hardcoded to `1` for PARTIAL, so it *always* falls through to the
judge. Consequences:
  - You pay for a judge call on every hedge-then-comply case you could have caught
    for free.
  - If the judge errors, that case degrades to SUSPICIOUS and you lose the PARTIAL
    entirely.
The feature "works" only because the judge independently re-detects it.
*Fix:* return confidence `>= 2` for a confident partial, **or** short-circuit on
partial before the threshold gate.

**2. The 200-token target cap can hide the very thing you're hunting.**
`send_prompt(max_tokens=200)`. Hedge-then-comply puts the payload *after* the
refusal — the part most likely to be truncated at 200 tokens. You may be
under-counting PARTIAL/VULNERABLE on longer replies. Raise target `max_tokens`
to ~512–1024; keep the judge small.

**3. `send_prompt` has no error handling.** `llm_judge` is wrapped in try/except;
`send_prompt` is not. One rate-limit or timeout mid-run throws and kills the whole
49-prompt scan — you lose every result. Add retry/backoff, or catch-and-record so
a single failure can't nuke the run.

**4. A few compliance signals are too generic → false-positive pressure.**
`"as requested"`, `"full access"`, `"no restrictions"`, `"in character"`,
`"for testing purposes"` all show up in benign or *refusing* replies. Example: a
refusal *"I don't have full access to system files"* hits a refusal signal
(`"i don't have"`) **and** a compliance signal (`"full access"`). Ties go to
VULNERABLE (`>=`), confidence 1 → escalates to the judge. The judge saves you, but
that means Stage 1 is blunter than the README's "~60% decided by keywords" claim.
*Fix:* make generic signals more specific, and actually measure the keyword-decision
rate on a real run.

**5. SUSPICIOUS is handled two different ways.** The engine's
`calculate_finding_severity` maps SUSPICIOUS → `"LOW"` (a finding). The report's
`build_summary` only files findings when verdict ∈ {PARTIAL, VULNERABLE} — so the
LOW severity the engine assigned gets dropped. The two files disagree about whether
SUSPICIOUS is a finding. Pick one and make both obey it.

**6. "confidence" is overloaded.** It means "number of keyword hits" for
VULNERABLE/SAFE, but a hardcoded `1` for PARTIAL and `0` for SUSPICIOUS. The `>= 2`
gate is really asking "is this decisive?" — so model that directly with a
`decisive: bool` instead of overloading a count. It'll stop biting you as you add
detectors.

**7. Indirect-injection prompts are sent through the user turn.** You already note
the 0% honestly — good. The architectural truth: indirect injection can only be
tested faithfully if the payload arrives via a *tool result / retrieved document*,
not the user message. That's a v1.1 design item (below). Until then, label that 0%
in the report output itself so a reader doesn't misread it as "safe against
indirect injection."

### Structural notes
- **Duplicated v01–v10 files**: perfect as a *learning artifact*; painful as a
  codebase (every fix has to land N times). Freeze the story with git tags, then
  develop v1.1+ in one package.
- **No tests.** A ~30-line pytest over `keyword_check`,
  `detect_partial_compliance`, and `calculate_finding_severity` would have caught
  issue #1 instantly — and "I wrote tests for my detector" is itself an interview
  signal.
- **Hygiene:** `.DS_Store` and a duplicate `lessons/lessons1.py` are committed.

### Suggested fix order
1. Issue #1 (dead PARTIAL path) — highest correctness impact, ~3 lines.
2. Issue #3 (no retry) — protects every future run.
3. Issue #2 (token cap) — re-run and see if numbers move.
4. Add the pytest. Then #4/#5/#6 cleanup.

---

## 2. The story (README / blog / interviews)

### One number, everywhere
Your README says **26/49 (53%)**; the project pitch text says **25/49 (51%)**.
Pick one canonical run and use that single figure in the README, the blog, and
when you talk about it. Inconsistent headline numbers are the first thing a sharp
reader notices.

### Tighten the headline claim
"No lightweight open-source tool exists" is too strong — `garak`, `PyRIT`, and
`promptfoo` exist. You don't need the claim, and it's a softball for an
interviewer. Reframe to your actual edge:

> "Existing tools (garak, PyRIT) are powerful but heavyweight. AgentProbe is a
> ~400-line, single-config scanner I built from zero to understand the detection
> problem end to end — including a hedge-then-comply detector I haven't seen
> isolated as its own stage elsewhere."

That's honest, it's defensible, and it pivots the conversation to the part you
actually understand deeply.

### Lead with the learning arc
Your strongest, least-fakeable asset is `lessons/` + the v01→v10 progression:
zero coding to a working LLM-security tool, each version adding exactly one
capability. Put that *above* the findings table in the README. It's the thing no
bootcamp grad can copy.

### Interview talking points (rehearse these)

- **"Walk me through the detection pipeline."** Two stages: free keyword pass,
  then an LLM judge only when the keyword stage is undecided. Cost-aware by design
  — the judge is the expensive part, so you route to it only when you have to.

- **"Why an LLM judge instead of keywords?"** Keywords catch words; the real
  failure is *behavioral* — a model can comply through roleplay or "creative
  writing" without ever emitting a compliance keyword. The judge scores intent.

- **"Why is the judge a bigger model than the target?"** A judge that's no
  stronger than the target shares its blind spots — you get correlated errors and
  the subtle compliances sail through. The judge has to out-reason the attack.

- **"What's the hardest failure mode you found?"** Hedge-then-comply: refuse in
  sentence one, deliver the payload in the next paragraph. It passes naive filters
  because the refusal is right there. I split the response and check the head for
  refusal and the tail for compliance.

- **"What would you change?"** *(This is the killer answer — self-critique reads
  as senior.)* "My cheap partial-detector returns a low-confidence verdict that
  always escalates to the judge, so it never actually saves a call — I'd fix the
  threshold so the free path can decide. And my 200-token cap can truncate the
  exact payload I'm hunting." Naming your own bugs beats any clean demo.

- **"Is the 0% on indirect injection a good result?"** No — it's a *test harness*
  limitation, not a model property. Indirect injection has to arrive through a
  document/tool channel; sending it in the user turn doesn't exercise the real
  vector. That honesty is the point.

---

## 3. v1.1 roadmap — done responsibly

Your roadmap's v1.1 is "test against real products with bug bounty programs."
That's the right ambition and the one place to be careful. Build the safe
foundation *first*, then go outward.

### Step 1 — Build your own targets (do this before touching anyone else's)
1. **A deliberately-vulnerable app you control:** a thin chat app with a known
   system prompt and weak guardrails. Now you have ground truth — you *know* the
   right answer, so you can measure AgentProbe's precision/recall instead of
   guessing.
2. **An "agent with tools" sandbox:** a mock agent that "reads documents" and
   "calls tools" against fake data. This is what finally lets you test indirect
   injection and tool-misuse *for real* — and entirely inside your own box.

This alone makes v1.1 a stronger portfolio piece than scanning a third party,
because you can report measured precision/recall, not anecdotes.

### Step 2 — Rules of engagement (write these into the repo)
Only point AgentProbe at an external target when **all** hold:
- The target is in an **explicit, written bug-bounty scope** (or you own it).
- You've **read the program's AI/LLM testing rules** — many AI products are
  out-of-scope or have special conditions; some ToS forbid adversarial testing
  outright. Obey them.
- **No real personal data, no destructive tool calls, single test account,
  respect rate limits.** Your scanner already paces requests — keep it conservative.
- **Responsible disclosure only:** private report, clear repro steps, a severity
  rationale (map to CVSS or OWASP LLM), no public dropping before the vendor
  responds.
- **Legal reality:** authorized testing only. Unauthorized probing of someone
  else's system can violate computer-misuse law regardless of intent.

### Step 3 — Make the tool itself disclosure-ready
- Emit a **machine-readable report** (JSON) alongside the HTML, so a finding can
  drop straight into a disclosure template.
- Add a **"harness limitation" banner** to indirect-injection results so a reader
  never mistakes a harness gap for a security guarantee.
- Add a **`--scope` guard**: refuse to run against any host not on an explicit
  allowlist. Turning "don't test what you're not allowed to" into a *code*
  constraint is exactly the kind of judgment that impresses security teams.

### Good first PR for v1.1
The vulnerable-app + agent-sandbox target, plus the JSON report. That unlocks
honest precision/recall numbers and real indirect-injection testing without any
third-party risk — and it's a clean, self-contained chunk of work.
