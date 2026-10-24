# LangChain quickstart agent as a scan target

This folder holds the target, the configs, and the recording behind
[`writeups/public-scan-01.md`](../../writeups/public-scan-01.md).

| File | What it is |
|---|---|
| `app.py` | The LangChain v1 "Build a basic agent" quickstart (`create_agent`, one `get_weather` tool, "You are a helpful assistant"), with the model string set to Groq's `openai/gpt-oss-20b`, behind a local HTTP endpoint on 127.0.0.1:8765 |
| `agentprobe.yaml` | The live scan: `http` target pointed at the app, `openai/gpt-oss-120b` on Groq as the judge, 49 attacks, no retries, the run recorded |
| `scan.replay.json` | The recording of that run: 49 agent responses and 49 judge replies, reviewed before commit |
| `replay.yaml` | Replays the recording offline. It needs no app, no keys, and no network |

## Replay the published run (offline)

```bash
pip install agentprobe-security
agentprobe scan --non-interactive --verbose \
  --config examples/langchain-quickstart-agent/replay.yaml
```

The replay serves the recorded responses through the same scanner code path
and reproduces every verdict and both operational errors.
`tests/test_public_scan.py` checks this on every CI run.

## Re-run it live

You need your own `GROQ_API_KEY`. A live run makes about 100 chat requests.
Results will differ: hosted models are not deterministic.

```bash
python -m venv .venv-agent && . .venv-agent/bin/activate
pip install "langchain>=1,<2" "langchain-groq>=1,<2"
GROQ_API_KEY=... python examples/langchain-quickstart-agent/app.py &

# in another shell, with agentprobe-security installed:
GROQ_API_KEY=... agentprobe scan --non-interactive --verbose \
  --config examples/langchain-quickstart-agent/agentprobe.yaml
curl -s http://127.0.0.1:8765/stats   # requests, model calls, retries, tool calls
```

Scan only agents you run yourself or are authorized in writing to test.
