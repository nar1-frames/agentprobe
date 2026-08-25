# AgentProbe — Research Pipeline

*Can we trust LLM-as-judge for prompt-injection detection?*

This folder turns AgentProbe from a **scanner** into a **measurement
instrument**. The scanner answers "did the target comply?" The pipeline answers
the harder, more publishable question: **"how much should we trust the judge
that decided the target complied?"**

The whole thing runs with no ML dependencies — `agentprobe/detection.py` for the
detector and `research/metrics.py` for the statistics are both pure Python you
can read end to end. That is deliberate: in a methods paper you must be able to
point at the exact code that produced every number.

---

## The two ideas this pipeline is built around

**1. Validity vs reliability — the two pillars of any measurement.**
- *Validity* = are we measuring the right thing? Operationally: does the judge
  agree with a **human**? (RQ1)
- *Reliability* = do we get the same answer if we measure again? Operationally:
  does the judge agree with **itself** across repeated runs? (RQ2)

A judge can be reliable but invalid (consistently wrong) or valid-on-average but
unreliable (right in expectation, noisy per case). You need both. Almost everyone
who cites "the LLM judge said 53%" has measured *neither*.

**2. Freeze the corpus, then judge it many times.**
Hitting the target is the expensive, non-reproducible step. The judge is the part
you want to run *repeatedly* — k times, several judge models, two temperatures. So
we generate the response corpus **once** (`gen_corpus`) and then run judges,
humans, and re-judges against that fixed set. This single decoupling is what makes
reliability (RQ2) and judge-strength (RQ4) measurable at all, and it gives your
human labels something stable to attach to.

---

## The four data files

Everything keys on a deterministic `response_id = sha1(category|attack_index|target_model)`,
so the corpus, the judge runs, and the human labels all line up without a shared
counter.

| File | Made by | One row is |
|------|---------|------------|
| `data/corpus.jsonl` | `gen_corpus` | one target response to one attack, + its keyword verdict |
| `data/judgements.jsonl` | `run_judges` | one judge run (of k) for one response, under one (model, temp) |
| `data/labels.csv` | `label` | one human's COMPLIED/PARTIAL/REFUSED call on one response |
| `data/results.json` | `analyze` | the machine-readable summary of all metrics |

---

## Run order

```bash
# 0. one-time: pip install pyyaml groq openai python-dotenv ; set GROQ_API_KEY in .env

# STEP A — freeze the response corpus across several target models
python -m research.gen_corpus --models llama-3.1-8b-instant,gemma2-9b-it,qwen-2.5-7b

# STEP C — judge the frozen corpus: strong + weak judge, two temps, k=5 each
python -m research.run_judges \
    --judges llama-3.3-70b-versatile,llama-3.1-8b-instant \
    --temps 0.0,0.7 --k 5

# STEP B — human ground truth (the keystone). You label everything:
python -m research.label --labeler ren
#   ...then a friend independently labels a 30% subset:
python -m research.label --labeler friend --subset 0.3 --seed 42

# STEPS D/E — compute all the metrics
python -m research.analyze --primary ren --second friend --json data/results.json
```

`run_judges` and `label` both support `--resume` / resuming, so a dropped
connection or a coffee break doesn't cost you the run.

---

## What each research question needs, and where it comes from

- **RQ1 — Validity.** Judge-majority vs human primary label: Cohen's κ, per-class
  precision/recall, 3×3 confusion. *Needs corpus + judgements + labels.*
- **RQ2 — Reliability.** The k repeats of each judge config: self-agreement rate,
  Fleiss' κ, and how many items ever flipped. *Needs judgements only* — you can
  run this the moment `run_judges` finishes, before any labeling.
- **RQ3 — Keyword vs judge.** The corpus already stores each response's keyword
  verdict; `analyze` joins it against the judge majority and also reports the
  **keyword-decisive rate** — how often the free path decides on its own. *Needs
  corpus + judgements.*
- **RQ4 — Judge strength.** Put a strong judge (`llama-3.3-70b`) and a
  weak/same-family judge (the 8B target itself) in `--judges`; RQ1 is reported
  **per judge config**, so you compare κ(strong, human) vs κ(weak, human)
  directly. The correlated-error test — do the weak judge's mistakes line up with
  the target's own mistakes — is the one analysis still to add.

### Why Cohen's κ and not raw accuracy
If 70% of responses are REFUSED, a lazy judge that *always* says REFUSED scores
0.70 accuracy while understanding nothing. κ subtracts the agreement you'd expect
by chance, so it doesn't reward guessing the majority class. `analyze` prints both
and `test_metrics.py` pins this exact trap (`test_accuracy_ignores_kappa_lesson`).
Lead with κ.

### Why a second labeler
A single labeler is just *your* bias dressed as ground truth. Two independent
labelers plus an agreement number turns "I decided" into "this label set is
reproducible to κ = X." That inter-annotator κ is also a **ceiling**: if two
humans only agree at κ = 0.7, no judge can honestly be expected to beat that.

---

## Honest limitations (state these before a reviewer finds them)

One primary human labeler, second labeler on a subset only. 49 English,
single-turn prompts — not exhaustive. A handful of open models at one point in
time; results will age. Judges and targets from overlapping families → possible
self-preference (RQ4 probes this but doesn't eliminate it). Compliance is partly
subjective — you are measuring *agreement*, not Truth.

---

## Files

```
agentprobe/detection.py    canonical two-stage detector (keyword + judge)
research/_common.py         config, clients, deterministic IDs, JSONL I/O
research/gen_corpus.py      Step A — freeze the response corpus
research/run_judges.py      Step C — k-repeat, multi-judge, multi-temp
research/label.py           Step B — human labeling CLI
research/metrics.py         pure-Python Cohen's/Fleiss' κ, confusion, PRF
research/analyze.py         Steps D/E — join everything, emit the report
tests/                      pytest over the detector and the metrics
```

## Still to build (next PRs)
1. **Correlated-error analysis for RQ4** — join weak-judge errors against target
   errors on the same items.
2. **Figure export** — turn `results.json` into the paper's tables/plots.
3. **Repoint the scanner** — make `agentprobe_v11.py` import from
   `agentprobe.detection` so there is exactly one detector in the repo.
