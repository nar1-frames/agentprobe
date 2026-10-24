"""The LangChain v1 quickstart agent, and the function AgentProbe calls to scan it.

The agent is the "Build a basic agent" example from the LangChain quickstart
(``create_agent`` with one ``get_weather`` tool and the system prompt "You are
a helpful assistant"), with the model string pointed at Groq. There are two
ways to scan it:

* python target: ``agentprobe.python.yaml`` names ``agent:answer``. The
  scanner imports this module and calls ``answer()`` once per attack, with no
  server in between.
* http target: ``app.py`` serves the same agent on 127.0.0.1:8765, and
  ``agentprobe.yaml`` points the scanner at it.

    pip install "langchain>=1,<2" "langchain-groq>=1,<2"

Both paths count every model call, so a scan can report exactly how many
provider requests it made.
"""

import logging
import os
import threading

from langchain.agents import create_agent
from langchain_core.callbacks import BaseCallbackHandler

MODEL = os.environ.get("AGENT_MODEL", "groq:openai/gpt-oss-20b")


# --- The quickstart agent, unchanged apart from the model string -------------
def get_weather(city: str) -> str:
    """Get weather for a given city."""
    return f"It's always sunny in {city}!"


agent = create_agent(
    model=MODEL,
    tools=[get_weather],
    system_prompt="You are a helpful assistant",
)
# -----------------------------------------------------------------------------

STATS = {"requests": 0, "model_calls": 0, "sdk_retries": 0, "tool_calls": 0, "errors": 0}
_LOCK = threading.Lock()


def _count(key, amount=1):
    with _LOCK:
        STATS[key] += amount


class ModelCallCounter(BaseCallbackHandler):
    """One count per chat-model invocation the agent makes."""

    def on_chat_model_start(self, serialized, messages, **kwargs):
        _count("model_calls")


class RetryCounter(logging.Handler):
    """The Groq SDK logs each automatic retry; each one is an extra request."""

    def emit(self, record):
        if record.getMessage().startswith("Retrying request"):
            _count("sdk_retries")


_retry_logger = logging.getLogger("groq")
_retry_logger.setLevel(logging.INFO)
_retry_logger.addHandler(RetryCounter())


def _reply_text(message):
    content = message.content
    if isinstance(content, str):
        return content
    return "".join(block.get("text", "") for block in content if isinstance(block, dict))


def run(prompt):
    """Send one user message to the agent; return its reply and the tools it called."""
    _count("requests")
    try:
        result = agent.invoke(
            {"messages": [{"role": "user", "content": prompt}]},
            config={"callbacks": [ModelCallCounter()]},
        )
    except Exception:
        _count("errors")
        raise
    tools = [m.name for m in result["messages"] if getattr(m, "type", "") == "tool"]
    _count("tool_calls", len(tools))
    return _reply_text(result["messages"][-1]), tools


def answer(prompt: str) -> str:
    """AgentProbe's python target: one attack in, the agent's reply out."""
    return run(prompt)[0]
