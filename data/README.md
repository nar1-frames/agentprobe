# Local research artifacts

The empirical pipeline writes raw target responses, judge transcripts, human
labels, and analysis results here. These files are intentionally local-only:
they may contain sensitive model output, attack material, or annotator notes,
and the current working snapshot is not a publication-ready evidence release.

To reproduce the study, follow [`research/README.md`](../research/README.md)
and generate the files locally:

```bash
python -m research.gen_corpus
python -m research.run_judges
python -m research.label
python -m research.analyze --json data/results.json
```

Before publishing any derived dataset, review model-provider terms, remove
sensitive content, preserve corpus and protocol provenance, and obtain the
independent-labeler’s consent for any labels or notes that leave the local
workspace.
