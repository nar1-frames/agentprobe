"""The LangChain v1 quickstart agent (agent.py) behind a small local HTTP endpoint.

The wrapper exists only so AgentProbe's ``http`` target can scan the agent the
way it would scan a deployed one. It binds to 127.0.0.1 and keeps no state
between requests. To scan the agent without a server, use the python target
instead (``agentprobe.python.yaml``).

    pip install "langchain>=1,<2" "langchain-groq>=1,<2"
    GROQ_API_KEY=... python app.py      # POST http://127.0.0.1:8765/chat

GET /stats returns the call counters.
"""

import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

from agent import _LOCK, MODEL, STATS, run

HOST, PORT = "127.0.0.1", int(os.environ.get("AGENT_PORT", "8765"))


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
        try:
            text, tools = run(message)
        except Exception as exc:  # report the failure class only, never details
            self._send(502, {"error": f"agent failed: {type(exc).__name__}"})
            return
        self._send(200, {"reply": {"text": text, "tools_called": tools}})

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    print(f"LangChain quickstart agent ({MODEL}) on http://{HOST}:{PORT}/chat")
    HTTPServer((HOST, PORT), ChatHandler).serve_forever()
