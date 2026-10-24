"""The LangChain v1 quickstart agent behind a small local HTTP endpoint.

The agent is the "Build a basic agent" example from the LangChain quickstart
(``create_agent`` with one ``get_weather`` tool and the system prompt "You are
a helpful assistant"), with the model string pointed at Groq. The wrapper
exists only so AgentProbe's ``http`` target can scan it. It binds to
127.0.0.1, keeps no state between requests, and counts every model call so a
scan can report exactly how many provider requests it made.

    pip install "langchain>=1,<2" "langchain-groq>=1,<2"
    GROQ_API_KEY=... python app.py      # POST http://127.0.0.1:8765/chat

GET /stats returns the call counters.
"""

import json
import logging
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from langchain.agents import create_agent
from langchain_core.callbacks import BaseCallbackHandler

MODEL = os.environ.get("AGENT_MODEL", "groq:openai/gpt-oss-20b")
HOST, PORT = "127.0.0.1", int(os.environ.get("AGENT_PORT", "8765"))


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


class ChatHandler(BaseHTTPRequestHandler):
    def _send(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/stats":
            with _LOCK:
                self._send(200, dict(STATS))
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/chat":
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            message = json.loads(self.rfile.read(length))["message"]
            if not isinstance(message, str):
                raise ValueError("message must be a string")
        except (ValueError, KeyError, TypeError):
            self._send(400, {"error": "expected JSON {\"message\": \"...\"}"})
            return
        _count("requests")
        try:
            result = agent.invoke(
                {"messages": [{"role": "user", "content": message}]},
                config={"callbacks": [ModelCallCounter()]},
            )
        except Exception as exc:  # report the failure class only, never details
            _count("errors")
            self._send(502, {"error": f"agent failed: {type(exc).__name__}"})
            return
        tools = [m.name for m in result["messages"] if getattr(m, "type", "") == "tool"]
        _count("tool_calls", len(tools))
        self._send(200, {"reply": {"text": _reply_text(result["messages"][-1]),
                                   "tools_called": tools}})

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    print(f"LangChain quickstart agent ({MODEL}) on http://{HOST}:{PORT}/chat")
    HTTPServer((HOST, PORT), ChatHandler).serve_forever()
