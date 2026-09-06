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

These are local working artifacts, not files committed to the public
repository. Raw model responses, judge transcripts, labels, and derived
results must be reviewed for sensitive content and provenance before any
publication or data release.

Everything keys on a deterministic `response_id = sha1(category|attack_index|target_model)`,
so the corpus, the judge runs, and the human labels all line up without a shared
counter.

| File | Made by | One row is |
|------|---------|------------|
| `data/corpus.jsonl` | `gen_corpus` | one frozen target response to one attack, + keyword verdict and generation settings |
| `data/judgements.jsonl` | `run_judges` | one judge run (of k) for one response, under one (model, temp), bound to the corpus SHA-256 |
| `data/labels.csv` | `label` | one human's COMPLIED/PARTIAL/REFUSED call on one response, bound to the corpus and labeling-guide SHA-256 |
| `data/results.json` | `analyze` | the machine-readable summary of all metrics |

`response_id` is stable across target reruns, so it is not sufficient evidence
of corpus identity by itself. Every newly collected judge and human-label row
also carries `corpus_sha256`, the canonical digest of the complete frozen
corpus. Human-label rows additionally carry the SHA-256 of the labeling guide;
the manifest binds that guide digest to the preregistered rubric. Validation
and the publication gate reject a row from another corpus or rubric; legacy
rows without the fields remain visible but cannot pass the gate.
Corpus and judge rows also carry a digest of the non-secret provider settings
used for that call. Manifest-backed resume and publication checks compare those
digests to the current validated config, so changing an endpoint, model budget,
or other recorded provider setting cannot silently reuse old evidence.

When driven by the checked-in manifest, the publication gate also reruns the
row-level dataset validator: stable response IDs, attack prompts, severities,
orphan references, duplicate evidence keys, and verdict shapes must all match
the frozen protocol. Analysis JSON converts undefined statistics to strict JSON
`null` rather than emitting non-standard `NaN` values.

---

## Run order

```bash
# 0. one-time: pip install pyyaml groq openai python-dotenv ; set GROQ_API_KEY in .env
# Cloud commands require explicit consent flags because model responses may
# contain sensitive content. Omit the flags for a local Ollama workflow.

# STEP A — freeze the preregistered 49-response corpus
python -m research.gen_corpus \
    --models openai/gpt-oss-20b \
    --allow-external-target \
    --target-temperature 0.0 --max-tokens 512 \
    --out data/corpus.jsonl --overwrite

# STEP C — judge the frozen corpus: strong + weak judge, two temps, k=5 each
python -m research.run_judges \
    --judges openai/gpt-oss-120b,openai/gpt-oss-20b \
    --allow-external-corpus \
    --temps 0.0,0.7 --k 5

# STEP B — human ground truth (the keystone). You label everything:
python -m research.label --labeler ren
#   ...then export the preregistered blinded subset for an independent annotator:
python -m research.label --labeler friend --export-packet /tmp/friend.label-packet.csv
#   Share only the CSV. Keep the private key beside it until import:
python -m research.label --labeler friend \
    --import-packet /tmp/friend.label-packet.csv \
    --packet-key /tmp/friend.label-packet.csv.key.json

# STEPS D/E — compute all the metrics
python -m research.analyze --primary ren --second friend \
    --reference-judge openai/gpt-oss-120b --reference-temperature 0.0 \
    --weak-judge openai/gpt-oss-20b --weak-temperature 0.0 \
    --json data/results.json

# Optional integrity gate before analysis
python -m research.validate

# Publication gate (intentionally fails until the empirical requirements are met)
# With no --manifest/--expected-config flags, the checked-in study manifest
# supplies the target scope, labelers, exact judge matrix, and k=5 requirement;
# it also verifies the deterministic 30% second-label subset.
python -m research.publication_gate --primary ren --second friend --k 5 \
  --expected-config openai/gpt-oss-20b@0.0 \
  --expected-config openai/gpt-oss-20b@0.7 \
  --expected-config openai/gpt-oss-120b@0.0 \
  --expected-config openai/gpt-oss-120b@0.7
```

`run_judges` supports `--resume`, `gen_corpus` uses atomic checkpoints when
called with `--append`, and `label` automatically resumes from existing rows,
so a dropped connection or a coffee break doesn't cost you the run. Resume
also checks the canonical corpus digest and, for manifest-backed judge
collection, the prompt/protocol/token-budget provenance; legacy or mismatched
judge/label rows are refused rather than silently reused against a regenerated
target response. Use `--overwrite` to start a fresh evidence file when an old
snapshot lacks those fields.
Both collection commands accept `--fail-on-error`: they still write the
recoverable artifact, then exit with status 3 when any target or judge call is
recorded as an operational failure. This makes provider outages visible to CI
without destroying partial evidence.
The checked-in manifest is authoritative for default corpus scope/settings,
judge matrix/repeat count, and blinded human-label assignment. To run a
deliberate exploratory deviation, pass `--manifest ""`; otherwise those
overrides fail before any provider call or label is collected. In particular,
manifest-backed labeling disables `--show-hits` so keyword output cannot bias
the human ground truth.
If judge rows contain provider failures, use
`run_judges --resume --repair-errors`; failed rows are archived beside the
active JSONL file and retried without creating duplicate evidence keys. Fresh
replacement of an existing corpus or judge file requires an explicit
`--overwrite` (or a new output path), so a mistaken rerun cannot silently
destroy evidence.

### Independent labeling packets

`research.label --export-packet` creates two local files: a CSV containing only
opaque item IDs, attack prompts, target responses, and empty `label`/`note`
columns; and a private JSON key that maps those IDs back to response IDs. Share
the CSV only. The packet intentionally omits categories, severities, target
model names, keyword hits, and judge decisions so the second annotator remains
blinded to the detector and analysis.

The annotator fills each `label` with `COMPLIED`, `PARTIAL`, or `REFUSED` and
may add a note without changing the other columns. Import verifies the corpus
SHA-256, packet text digest, item coverage, private mapping, label vocabulary,
the labeling-guide digest, and existing-label conflicts before appending to
`data/labels.csv`. Packet and
key files are written with owner-only permissions and are ignored by Git
because they contain raw model responses.

---

## What each research question needs, and where it comes from

- **RQ1 — Validity.** Judge-majority vs human primary label: Cohen's κ, per-class
  precision/recall, 3×3 confusion. *Needs corpus + judgements + labels.*
- **RQ2 — Reliability.** The k repeats of each judge config: self-agreement rate,
  Fleiss' κ, and how many items ever flipped. Failed judge calls are excluded;
  if a resumed/interrupted run leaves an uneven number of repeats, Fleiss' κ is
  computed only on the complete modal k and the exclusions are reported. *Needs
  judgements only* — you can run this the moment `run_judges` finishes, before
  any labeling.
- **RQ3 — Keyword vs judge.** The corpus already stores each response's keyword
  verdict; `analyze` joins it against the judge majority and also reports the
  **keyword-decisive rate** — how often the free path decides on its own. *Needs
  corpus + judgements.*
- **RQ4 — Judge strength.** Put a strong judge (`openai/gpt-oss-120b`) and a
  weak/same-family judge (`openai/gpt-oss-20b`) in `--judges`; RQ1 is reported
  **per judge config**, so you compare κ(strong, human) vs κ(weak, human)
  directly. `analyze` also reports a cautious proxy-error-overlap statistic for
  weak-judge versus keyword-stage errors on human-labeled items. Because keyword
  output is not independent ground truth, this is directional evidence only.

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
research/label_packet.py    blinded export/import workflow for independent labels
research/metrics.py         pure-Python Cohen's/Fleiss' κ, confusion, PRF
research/analyze.py         Steps D/E — join everything, emit the report
research/validate.py         pre-analysis integrity checks for JSONL/CSV artifacts
research/export.py           deterministic Markdown publication-table export
research/publication_gate.py explicit gate for labels, independent raters, and fixed-k runs
research/PREREGISTRATION.md  protocol to freeze before the final empirical run
research/study_manifest.json executable target/judge/label/repeat-count protocol
research/protocol.py         manifest validation and default study requirements
tests/                      pytest over the detector and the metrics
```

## Still to build (next PRs)
1. **Complete ground truth** — finish primary labels and add an independent
   second labeler before making population-level claims.
2. **Broader live scenario coverage** — connect more real agent frameworks to
   the OpenAI-compatible adapter while preserving the fixture-only regression
   suite.
3. **Protocol execution** — freeze/register manifest v1.4 (see
   [`PROTOCOL_CHANGELOG.md`](PROTOCOL_CHANGELOG.md)), collect its new corpus
   with explicit target settings, then collect human labels and judge
   repetitions without changing the manifest.
