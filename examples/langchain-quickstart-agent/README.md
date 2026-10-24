# LangChain quickstart agent as a scan target

This folder holds the target, the configs, and the recording behind
[`writeups/public-scan-01.md`](../../writeups/public-scan-01.md). It shows the
two ways to scan an agent you can run yourself: over HTTP, the way you would
scan a deployed agent, and as a Python function, with no server.

| File | What it is |
|---|---|
| `agent.py` | The LangChain v1 "Build a basic agent" quickstart (`create_agent`, one `get_weather` tool, "You are a helpful assistant"), with the model string set to Groq's `openai/gpt-oss-20b`. `answer(prompt)` is the function the python target calls |
| `app.py` | The http wrapper: serves the same agent on 127.0.0.1:8765 |
| `agentprobe.yaml` | The live scan over HTTP: `http` target pointed at `app.py`, `openai/gpt-oss-120b` on Groq as the judge, 49 attacks, no retries, the run recorded |
| `agentprobe.python.yaml` | The same scan through the python target: the scanner imports `agent.py` and calls `answer()` directly |
| `scan.replay.json` | The recording of the public-scan-01 run (over HTTP): 49 agent responses and 49 judge replies, reviewed before commit |
| `replay.yaml` | Replays the recording offline. It needs no agent, no keys, and no network |

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

**Over HTTP**, with the agent in its own environment:

```bash
python -m venv .venv-agent && . .venv-agent/bin/activate
pip install "langchain>=1,<2" "langchain-groq>=1,<2"
GROQ_API_KEY=... python examples/langchain-quickstart-agent/app.py &

# in another shell, with agentprobe-security installed:
GROQ_API_KEY=... agentprobe scan --non-interactive --verbose \
  --config examples/langchain-quickstart-agent/agentprobe.yaml
curl -s http://127.0.0.1:8765/stats   # requests, model calls, retries, tool calls
```

**As a Python function**, with the agent and the scanner in one environment:

```bash
pip install agentprobe-security "langchain>=1,<2" "langchain-groq>=1,<2"
GROQ_API_KEY=... agentprobe scan --non-interactive --verbose \
  --config examples/langchain-quickstart-agent/agentprobe.python.yaml
```

The python target needs no port and no request template, and it reaches the
agent the same way your own code does. The http target tests what a client
would actually reach, including the web layer. Both configs use the same target
label and settings, so the two paths send identical requests and a recording
made through one replays through the other. [docs/TARGETS.md](../../docs/TARGETS.md)
compares the target types.

Scan only agents you run yourself or are authorized in writing to test.
