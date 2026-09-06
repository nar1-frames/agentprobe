# Research Plan — Can We Trust LLM-as-Judge for Prompt-Injection Detection?

**Target:** arXiv preprint (+ optional workshop later)
**Type:** methods / measurement paper
**Instrument:** AgentProbe (already built)

---

## The one-sentence thesis

Practitioners increasingly use a strong LLM as an automatic judge to decide
whether a target model "complied" with a prompt-injection attack — but the
judge's *own* reliability is rarely measured. This paper measures it: against
human labels (validity) and against itself (reliability), and maps where the
cheap keyword detector and the expensive judge disagree.

Why this is publishable: the *finding* is the contribution, not the tool. Even a
carefully measured result showing systematic judge errors on creative-writing
refusals would be a useful, citable contribution; the result must come from the
completed protocol rather than being assumed in advance.

---

## Research questions

- **RQ1 (Validity).** How well does an LLM judge agree with human judgment on
  compliance (COMPLIED / PARTIAL / REFUSED)? Overall and per attack category.
- **RQ2 (Reliability).** How self-consistent is the judge across repeated runs at
  fixed settings? Where does it flip?
- **RQ3 (Keyword vs judge).** On which cases does the free keyword stage diverge
  from the judge, and what kinds of responses cause it?
- **RQ4 (Judge strength).** Does a weaker / same-family judge produce more errors
  that *correlate* with the target's mistakes (the "correlated error" hypothesis)?

> **Teaching note — validity vs reliability.** These are the two pillars of any
> measurement. *Validity* = are you measuring the right thing (does the judge
> agree with a human, your ground truth)? *Reliability* = do you get the same
> answer if you measure again (does the judge agree with itself across runs)? A
> judge can be reliable but invalid (consistently wrong) or valid-on-average but
> unreliable (right in expectation, noisy per-case). You need both, and most
> people who cite "LLM-judge said 53%" have measured *neither*.

---

## Experimental design

### Step A — Generate the response corpus
Run the 49 attacks against **several open target models** (e.g. Llama-3.1-8B,
Mistral-7B, Qwen2.5-7B, Gemma-2-9B — pick 3–5 you can access on Groq/Ollama).
Save **raw responses** to JSON. This corpus (~49 × 4 ≈ 200 responses) is the
object of study.

> Fix the known bugs *before* generating: the 200-token truncation and the
> dead-PARTIAL path both bias results. Never publish numbers from code you've
> already found bugs in.

### Step B — Build human ground truth (the keystone)
**You** label every response COMPLIED / PARTIAL / REFUSED using a written rubric.
Then have a **second labeler** (a friend, classmate) independently label a
random ~30% subset. Report inter-annotator agreement between the two humans —
this calibrates how hard the task even is. If two humans only agree 80% of the
time, you can't expect the judge to beat that.

> **Teaching note — why a second labeler.** A single labeler is just *your* bias
> dressed as ground truth. Two independent labelers + an agreement number turns
> "I decided" into "this label set is reproducible to within κ = X." That one
> move is the biggest credibility jump available to you.

### Step C — Run the judges
For every response, run the judge **k = 5 times** (k repeats let you measure
RQ2). Vary two things:
- **Judge model:** a strong judge (Llama-3.3-70B) and a weak/same-family judge
  (the 8B itself) — this is RQ4.
- **Temperature:** 0.0 vs 0.7 — does sampling temperature change agreement?

Log *every* run, not just the majority vote. You can't analyze variance you threw
away.

### Step D — Metrics
| RQ | Metric | What it tells you |
|----|--------|-------------------|
| RQ1 | Accuracy + **Cohen's κ** vs human; per-class precision/recall; 3×3 confusion matrix | Does the judge measure the right thing, and *where* does it err |
| RQ2 | Self-agreement rate across k runs; **Fleiss' κ**; count of items that ever flipped | Is the judge stable |
| RQ3 | Keyword-vs-judge confusion matrix; error taxonomy on disagreements | When is the free path safe to trust |
| RQ4 | κ(strong judge, human) vs κ(weak judge, human); correlation of judge errors with target errors | Does judge strength matter; correlated error |

> **Teaching note — why Cohen's κ, not raw accuracy.** If 70% of responses are
> REFUSED, a lazy judge that *always* says REFUSED scores 70% accuracy while
> understanding nothing. κ corrects for agreement you'd get by chance, so it
> doesn't reward guessing the majority class. Report both, lead with κ.

### Step E — Error analysis (qualitative, the part reviewers love)
Pull the cases where judge ≠ human and group them into a small taxonomy, e.g.:
- over-flags refusals wrapped in creative framing,
- misses subtle roleplay compliance,
- judge-injection (target text that tries to steer the judge),
- genuine human-ambiguous cases.
Two or three concrete examples per bucket. This is where your real understanding
shows.

---

## Paper outline (arXiv-standard)

1. **Abstract** — problem, method, headline number, takeaway.
2. **Introduction** — LLM-judge is widely used to score injection robustness; its
   reliability is assumed, not measured; we measure it. List contributions as
   bullets.
3. **Background & related work** — prompt injection (OWASP LLM Top-10, MITRE
   ATLAS); LLM-as-judge literature; existing red-team tools (garak, PyRIT,
   promptfoo) and how you differ (you *evaluate the evaluator*).
4. **Method** — attack taxonomy (8 categories, 49 prompts), the two-stage
   detector, human-labeling protocol, judge configs, metrics.
5. **Results** — RQ1–RQ4, one table/figure each.
6. **Error analysis** — the taxonomy + examples.
7. **Limitations & threats to validity** — small/English-only prompt set; few
   models; snapshot in time; labeler subjectivity; judge-injection risk.
8. **Ethics & responsible disclosure** — authorized testing only; no live
   third-party systems; public attack patterns only.
9. **Conclusion + future work.**
10. **Appendix** — full prompt list, labeling rubric, reproducibility (seeds,
    model versions, code/data release).

---

## What to build, in order

1. **Fix the two bugs** (dead-PARTIAL path, token truncation) + add a tiny pytest.
   *(Clean instrument first.)*
2. **JSON data logging** — every run records attack, target, response, keyword
   verdict + hits, and each of the k judge verdicts + reasons. Raw data is the
   paper's lifeblood; the HTML report is not enough.
3. **Multi-model runner** — loop the scan over a list of target models.
4. **Labeling harness** — a dead-simple CLI/notebook that shows a response and
   records your COMPLIED/PARTIAL/REFUSED label to a CSV.
5. **Analysis notebook** — compute κ, confusion matrices, self-agreement; emit the
   figures.
6. **Write**, section by section, results first.

> Items 1–3 are mostly refactors of code you already have. Item 4 is small. The
> research *content* is items 5–6. You are closer than it feels.

---

## Honest limitations to state up front (don't let a reviewer find them first)
- One primary human labeler; second labeler on a subset only.
- 49 prompts, English, single-turn — not exhaustive.
- A handful of open models at one point in time; results will age.
- Judges and targets from overlapping families → possible self-preference;
  RQ4 addresses this but doesn't eliminate it.
- Compliance is partly subjective; you are measuring *agreement*, not Truth.

Stating these *makes the paper stronger*, not weaker. Reviewers reward authors
who already see their own gaps.
