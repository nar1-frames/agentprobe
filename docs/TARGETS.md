# Targets

The `target` block names what a scan attacks. There are four kinds. The
`judge` block is always a model you control (`groq`, `openai`, `ollama`,
`custom`, or `replay`), never an agent.

| Target | Provider | What it tests | Use it when |
|---|---|---|---|
| A model | `groq`, `openai`, `ollama`, `custom` | The model alone, with an optional system prompt | You are choosing a model or a system prompt |
| A deployed agent | `http` | Everything a client reaches: prompt, tools, retrieval, guardrails, and the web layer | The agent runs behind an endpoint, including someone else's under a signed authorization |
| An agent function | `python` | The agent your code builds, called in-process | You have the agent's code and want to scan it without a server |
| A recording | `replay` | Nothing new: it serves the responses of an earlier run | You need an offline, repeatable run, in CI or a demo |

## A model

```yaml
target:
  provider: groq                     # or openai, ollama, custom
  model: openai/gpt-oss-20b
  api_key_env: GROQ_API_KEY          # required for groq and openai
  system_prompt: "You are a support assistant for Acme."   # optional
  max_tokens: 512
  temperature: 0.0
```

`ollama` talks to `http://localhost:11434/v1` unless `base_url` says
otherwise. `custom` is any OpenAI-compatible endpoint and requires `base_url`.
`agentprobe scan` with no config opens a picker of the local and cloud models
available to you.

## A deployed agent: `http`

The scanner sends each attack to your endpoint in the endpoint's own JSON
shape and reads the reply from a path you name. Every attack gets a fresh
session ID by default.

```yaml
target:
  provider: http
  model: acme-support-bot            # a label for the report
  base_url: https://app.example.com/api/chat
  api_key_env: ACME_SCAN_TOKEN       # sent as Authorization: Bearer <token>
  strength_rank: 1                   # required: the agent does not reveal its model
  http:
    request_template: {message: "{{prompt}}", session_id: "{{session_id}}"}
    response_path: reply.text        # dotted path, e.g. choices[0].message.content
```

| Setting | Meaning |
|---|---|
| `request_template` | The JSON body. Strings may use `{{prompt}}`, `{{system_prompt}}`, `{{model}}`, and `{{session_id}}`. A string that is exactly `{{messages}}` becomes the whole message list. It must use `{{prompt}}` or `{{messages}}` |
| `response_path` | Where the reply text is in the JSON response. Leave it out for a plain-text body |
| `method` | `POST` (default) or `PUT` |
| `headers` | Static, non-secret headers. Credential headers are refused; use `api_key_env` |
| `auth_header`, `auth_scheme` | Default `Authorization` and `Bearer`. An empty scheme sends a bare token |
| `session` | `fresh` (default, a new ID per attack) or `shared` (one ID for the scan) |

HTTP errors are recorded by status code without the response body, which may
echo your token. Replies over 4 MiB are refused.

## An agent function: `python`

The scanner imports a function from your code and calls it once per attack.
There is no server, port, or request template.

```yaml
target:
  provider: python
  model: my-agent                    # a label for the report
  strength_rank: 1                   # required: the function does not reveal its model
  python:
    callable: "my_agent.chat:answer"   # package.module:function
    cwd: ..                          # optional; see below
    messages: false                  # optional; see below
```

| Setting | Meaning |
|---|---|
| `callable` | `package.module:function`. After the colon a dotted path is allowed, for example `app:agent.answer` |
| `cwd` | A directory put first on `sys.path` before the import. A relative path is resolved next to the config file. The default is the config file's own directory. The scanner's working directory does not change |
| `messages` | `false` (default) calls `function(prompt: str) -> str` with the attack text. `true` calls `function(messages: list[dict]) -> str` with the chat-completions message list, which includes the system message when `target.system_prompt` is set. `system_prompt` without `messages: true` is refused, because the function would never see it |

How it behaves:

- **Import once, before any attack.** A function that cannot be imported (a
  missing module, a typo in the name, an import that raises, even one that
  calls `sys.exit()`) stops the scan with a configuration error (exit code 2)
  before anything is sent.
- **Failures are evidence, not crashes.** An exception raised by the function,
  a reply that is not a `str`, or an empty reply becomes that attack's
  operational error, exactly like a failed HTTP call. The scan continues.
  Exceptions pass through unchanged, so a rate-limit error raised inside your
  agent is retried under `scan.retries` like any provider's. Ctrl-C still
  stops the scan.
- **`async def` works.** An awaitable result is run to completion.
- **Settings the function does not receive.** `max_tokens`, `temperature`, and
  `reasoning_effort` are not passed to the function; they still identify each
  request in a recording. `timeout_seconds` is not enforced: the function runs
  in the scanner process, so give your agent its own timeouts.
- **Record and replay work.** With `scan.record_replay_path` set, every reply
  is recorded. A recording made through a python target and one made through
  an `http` target are interchangeable when the label and settings match.
- **It is code.** A config that names a python target runs that code with your
  permissions when scanned. Scan only configs you trust. The function and its
  dependencies must be installed in the same environment as AgentProbe.

### Example: benchmark 01 without its server

[examples/benchmark-01/app.py](../examples/benchmark-01/app.py) serves three
configurations of the LangChain quickstart agent over HTTP. To scan the
hardened one directly, save this beside `app.py` as `scan_target.py`:

```python
from app import AGENTS, _reply_text


def hardened(prompt: str) -> str:
    result = AGENTS["hardened"].invoke({"messages": [{"role": "user", "content": prompt}]})
    return _reply_text(result["messages"][-1])
```

and point a config in the same folder at it:

```yaml
target:
  provider: python
  model: quickstart-hardened
  strength_rank: 1
  python:
    callable: "scan_target:hardened"
```

Importing `app` builds the three agents but does not start the server, which
only runs under `if __name__ == "__main__"`. Copy the `judge`, `scan`, and
`output` blocks from `examples/benchmark-01/hardened/agentprobe.yaml`. The
label and settings match the recorded HTTP run, so `hardened/replay.yaml`
would replay this config's requests too.
[examples/langchain-quickstart-agent](../examples/langchain-quickstart-agent/README.md)
ships both wrappers side by side.

### http or python?

Use `http` when the thing you ship is an endpoint: it tests what a client
actually reaches, including request parsing, authentication, and any filter in
the web layer. Use `python` when you are building the agent and want a fast
loop with no server, or when the agent has no endpoint yet. A python scan says
nothing about the layers it skips.

## A recording: `replay`

```yaml
target:
  provider: replay
  model: langchain-quickstart-agent  # must match the recorded run
  replay_path: scan.replay.json      # resolved next to this config file
  strength_rank: 1
```

Record by setting `scan.record_replay_path` in a live config. Replay by
pointing both `target` and `judge` at the recording. Model names and
generation settings must match the recorded run, because each response is
keyed by the SHA-256 of its request. A request with no recorded response is an
operational error, never a fabricated reply. Recordings hold raw model output:
keep them out of version control unless you have reviewed them.
`agentprobe demo` is a replay of a recording that ships with the package.
