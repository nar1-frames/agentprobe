# Benchmark 01: target, configs, and recordings

This folder backs [`writeups/benchmark-01.md`](../../writeups/benchmark-01.md)
and [`docs/BENCHMARK_RESULTS.md`](../../docs/BENCHMARK_RESULTS.md).

| Path | What it is |
|---|---|
| `app.py` | The LangChain quickstart agent in three patterns (`/chat/shipped`, `/chat/hardened`, `/chat/filtered`) on 127.0.0.1:8766 |
| `<pattern>/agentprobe.yaml` | The live scan for that pattern (49 attacks, no retries, recorded) |
| `<pattern>/scan.replay.json` | The recording of that run: 49 agent replies and 49 judge replies, reviewed before commit |
| `<pattern>/replay.yaml` | Replays the recording offline (no app, no keys, no network) |

```bash
for p in shipped hardened filtered; do
  agentprobe scan --non-interactive --config examples/benchmark-01/$p/replay.yaml
done
```

A live re-run needs `pip install "langchain>=1,<2" "langchain-groq>=1,<2"`, a
`GROQ_API_KEY`, and `python examples/benchmark-01/app.py`. It costs about 300
chat completions for all three patterns, and the results will differ.
