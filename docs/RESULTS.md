# Results and provenance

This file separates the headline pilot scan from the frozen research dataset.
They answer different questions and must not be reported as if they were one
experiment.

## Historical pilot scan

The July 14, 2026 v1.1 scan used `llama-3.1-8b-instant` as the target and
`llama-3.3-70b-versatile` as the judge across the 49-prompt library. Its saved
local HTML artifact reported **29/49 findings (59%)**: 27 VULNERABLE and 2
PARTIAL, with 10 CRITICAL, 15 HIGH, and 4 MEDIUM findings.

This is a dated scanner snapshot. The model responses and provider behavior can
change, and HTML reports are intentionally ignored by Git. It is useful as the
project's engineering baseline, but it is not the final population-level claim
of the judge study.

## Frozen judge study snapshot

The historical local research snapshot contained the following artifacts. Raw
responses, judge transcripts, and labels are intentionally excluded from the
public tree because they can contain sensitive model output and annotator
notes; the counts below are retained as provenance for the development
snapshot, not as a public evidence release:

- 49 frozen responses from `llama-3.1-8b-instant`;
- 530 judge rows across two judge models, two temperatures, and repeated runs;
- 17 primary human labels; and
- 5 recorded judge API failures, excluded from reliability statistics.

The canonical corpus digest recorded for that local snapshot was
`e29b471f4d5cb201dbce9d8c12f13fb958b3c516b5075b5aa6aa12e5ab49418c`.
The historical snapshot used the then-current v1.1 manifest file SHA-256
`73d95dc65182f95c387bab4a928cb16051a7e070d0b36890a55eec2d1cc9043d` and
canonical protocol digest
`c4d78ec8f23c98b99d1e27cc2ba0661ec42d63d292fe0b9414c0f2f68d58d10d`.
The checked-in executable manifest is now protocol v1.4, with its model,
reasoning, and text-only-context migrations
documented in `research/PROTOCOL_CHANGELOG.md`; it defines a new
study corpus and must not be joined to this historical snapshot.
The v1.4 manifest file SHA-256 is
`a1733a8e6140a39c36b5690fc6b34fb2af607a7e0b4e24dd8231b307ae893f26`, and its
canonical protocol digest is
`55162ce2b70a4bf23c09dd32ce5526786fcbddc6c2ea803b198f1c9bde7596e1`.
The manifest now pins the target and judge providers, target generation at
temperature `0.0` and `max_tokens=512`, and judge output at `max_tokens=120`;
it also pins the SHA-256 of `research/LABELING_GUIDE.md`.
the historical corpus predates that explicit metadata and therefore cannot
pass the publication gate without a controlled corpus regeneration. It also
pins the version and digest of the judge prompt; the historical judge rows
predate those provenance fields and the corpus digest field; they must be
regenerated before publication. The 17 historical label rows likewise lack
corpus and labeling-guide binding and cannot be reused after regeneration.

The last local analysis of that snapshot used complete modal repeat groups for
Fleiss' κ:

| Judge | Temperature | Complete items | k | Self-agreement | Fleiss' κ |
|---|---:|---:|---:|---:|---:|
| `llama-3.1-8b-instant` | 0.0 | 49 | 3 | 1.000 | 1.000 |
| `llama-3.1-8b-instant` | 0.7 | 49 | 3 | 0.844 | 0.449 |
| `llama-3.3-70b-versatile` | 0.0 | 49 | 3 | 0.993 | 0.973 |
| `llama-3.3-70b-versatile` | 0.7 | 28 | 3 | 0.988 | 0.952 |

The 70B/0.7 condition has 5 failed calls and 21 incomplete response groups;
the exclusions are shown by `research.analyze` rather than silently filled.
With the configured 70B judge at temperature 0.0, the keyword-vs-judge raw
agreement was **0.449**, and the keyword stage made a decisive call on **5/49
(10.2%)** responses.

The analysis command also emits an RQ4 proxy-error-overlap result on the 17
human-labeled items. It compares weak-judge errors with keyword-stage errors,
but treats keyword output as a target-behavior proxy—not independent ground
truth—so it is directional evidence only.

Validity was still preliminary because only 17 responses had human labels. The
snapshot's Cohen's κ values against those labels were -0.007 (8B/0.0), 0.040
(8B/0.7), -0.054 (70B/0.0), and -0.172 (70B/0.7). These numbers are evidence
that the labeling and judge protocol needs more ground truth, not a basis for a
general claim about model quality.

## Reproduce the snapshot analysis

```bash
python -m research.validate
python -m research.publication_gate --primary ren --second friend --k 5 \
    --expected-config openai/gpt-oss-20b@0.0 \
    --expected-config openai/gpt-oss-20b@0.7 \
    --expected-config openai/gpt-oss-120b@0.0 \
    --expected-config openai/gpt-oss-120b@0.7
python -m research.analyze --primary ren \
    --reference-judge openai/gpt-oss-120b \
    --reference-temperature 0.0 \
    --weak-judge openai/gpt-oss-20b \
    --weak-temperature 0.0 \
    --json /tmp/agentprobe-results.json
python -m research.export --results /tmp/agentprobe-results.json \
    --out /tmp/agentprobe-results.md
```

## Publication gate

The public repository currently contains no raw response corpus or completed
label release, so the historical snapshot cannot be reproduced from a clean
clone alone. Before calling a new study publication-ready, complete all 49 primary labels,
obtain a blinded independent second labeler on a preregistered subset, and rerun
every judge condition with the intended fixed `k` and no unexplained missing
groups. The software now reports deterministic bootstrap intervals for validity
and reliability; the remaining analysis work is to preregister and execute the
correlated-error analysis on the completed data. The `research.publication_gate`
command encodes the data-completeness requirements and exits nonzero until they
are satisfied. With the manifest-backed defaults it also validates every
corpus, judge, and label row against the frozen attack library and evidence
keys before returning `READY`.
