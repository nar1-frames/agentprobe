"""Scan a deployed agent over plain HTTP instead of a raw model API.

The other providers speak the OpenAI chat-completions protocol, which means
they test a *model*. A customer's agent is a model plus a system prompt, tools,
retrieval, and guardrails, reachable only through the customer's own endpoint
with its own JSON shape. This adapter makes such an endpoint look like a
chat-completions client, so the scanner, the record/replay layer, and the
reports work unchanged.

Only the ``target`` block may use it: the judge must be a model the operator
controls. Each attack is sent in a fresh session by default so one prompt
cannot poison the next. Configuration (all under ``target.http``):

- ``request_template`` (required): the JSON body to send. Strings may contain
  ``{{prompt}}`` (the attack text), ``{{system_prompt}}``, ``{{model}}``, or
  ``{{session_id}}``; a string that is exactly ``{{messages}}`` becomes the
  whole chat-completions message list. The template must reference
  ``{{prompt}}`` or ``{{messages}}`` or nothing would be tested.
- ``response_path`` (optional): dotted path into the JSON reply, for example
  ``reply.text`` or ``choices[0].message.content``. Omit it to read the
  response body as plain text.
- ``method`` (``POST`` default or ``PUT``), ``headers`` (static, non-secret),
  ``auth_header`` (``Authorization`` default) and ``auth_scheme``
  (``Bearer`` default, empty string for a bare token).
- ``session``: ``fresh`` (default, a new UUID per request) or ``shared``
  (one UUID for the whole scan).

The bearer token still comes from ``api_key_env``; static headers may not
carry credentials, so a committed config never leaks one.
"""

from __future__ import annotations

import json
import os
import re
import socket
import uuid
from types import SimpleNamespace
from typing import Any, Mapping, Optional
from urllib import error, request
from urllib.parse import urlparse

from agentprobe.detection import sanitize_error


PLACEHOLDERS = ("prompt", "system_prompt", "model", "session_id")
MESSAGES_PLACEHOLDER = "{{messages}}"
VALID_METHODS = frozenset({"POST", "PUT"})
VALID_SESSIONS = frozenset({"fresh", "shared"})
_PLACEHOLDER_RE = re.compile(r"\{\{\s*([a-z_]+)\s*\}\}")
_PATH_TOKEN_RE = re.compile(r"([^.\[\]]+)|\[(\d+)\]")
# Headers that would carry a credential in a committed config file.
_CREDENTIAL_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie", "x-api-key", "api-key",
})
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class HttpTargetError(RuntimeError):
    """An endpoint failure, carrying the HTTP status so retries can classify it."""

    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status_code = status


def _template_mentions(template: Any, names: set) -> None:
    """Collect every placeholder name used anywhere in ``template``."""

    if isinstance(template, str):
        if template.strip() == MESSAGES_PLACEHOLDER:
            names.add("messages")
        else:
            names.update(_PLACEHOLDER_RE.findall(template))
    elif isinstance(template, Mapping):
        for value in template.values():
            _template_mentions(value, names)
    elif isinstance(template, (list, tuple)):
        for value in template:
            _template_mentions(value, names)


def validate_http_block(block: Any, name: str = "target.http") -> dict:
    """Validate the ``http`` settings and return a normalized copy.

    This runs at config time so a typo fails before the first attack is sent.
    """

    if not isinstance(block, Mapping):
        raise ValueError(f"{name} must be a mapping")
    method = str(block.get("method", "POST")).upper()
    if method not in VALID_METHODS:
        raise ValueError(f"{name}.method must be one of {', '.join(sorted(VALID_METHODS))}")
    headers = block.get("headers", {}) or {}
    if not isinstance(headers, Mapping):
        raise ValueError(f"{name}.headers must be a mapping")
    for key, value in headers.items():
        if not isinstance(key, str) or not key.strip() or not isinstance(value, str):
            raise ValueError(f"{name}.headers entries must be string: string")
        if key.strip().lower() in _CREDENTIAL_HEADERS:
            raise ValueError(
                f"{name}.headers must not contain {key!r}; put the secret in an "
                "environment variable and name it with api_key_env"
            )
    auth_header = block.get("auth_header", "Authorization")
    if not isinstance(auth_header, str) or not auth_header.strip():
        raise ValueError(f"{name}.auth_header must be a non-empty string")
    auth_scheme = block.get("auth_scheme", "Bearer")
    if not isinstance(auth_scheme, str):
        raise ValueError(f"{name}.auth_scheme must be a string (empty for a bare token)")
    template = block.get("request_template")
    if not isinstance(template, Mapping) or not template:
        raise ValueError(f"{name}.request_template must be a non-empty JSON object")
    try:
        json.dumps(template, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name}.request_template must be JSON-serializable: {exc}") from exc
    used: set = set()
    _template_mentions(template, used)
    unknown = sorted(used - set(PLACEHOLDERS) - {"messages"})
    if unknown:
        raise ValueError(f"{name}.request_template uses unknown placeholders: {unknown}")
    if not used & {"prompt", "messages"}:
        raise ValueError(
            f"{name}.request_template must reference {{{{prompt}}}} or {{{{messages}}}}; "
            "otherwise the attack text is never sent"
        )
    response_path = block.get("response_path")
    if response_path is not None:
        if not isinstance(response_path, str) or not response_path.strip():
            raise ValueError(f"{name}.response_path must be a non-empty string or null")
        parse_response_path(response_path)  # raises on malformed paths
    session = block.get("session", "fresh")
    if session not in VALID_SESSIONS:
        raise ValueError(f"{name}.session must be one of {', '.join(sorted(VALID_SESSIONS))}")
    return {
        "method": method,
        "headers": {key.strip(): value for key, value in headers.items()},
        "auth_header": auth_header.strip(),
        "auth_scheme": auth_scheme.strip(),
        "request_template": json.loads(json.dumps(template)),
        "response_path": response_path.strip() if response_path else None,
        "session": session,
    }


def parse_response_path(path: str) -> list:
    """Turn ``reply.choices[0].text`` into ``["reply", "choices", 0, "text"]``."""

    tokens: list = []
    position = 0
    text = path.strip()
    while position < len(text):
        if text[position] == ".":
            position += 1
            continue
        match = _PATH_TOKEN_RE.match(text, position)
        if not match:
            raise ValueError(f"response_path is malformed near {text[position:]!r}")
        tokens.append(int(match.group(2)) if match.group(2) is not None else match.group(1))
        position = match.end()
    if not tokens:
        raise ValueError("response_path must name at least one field")
    return tokens


def extract_response_text(body: Any, path: Optional[str]) -> str:
    """Pull the agent's reply out of a decoded JSON body (or raw text)."""

    if path is None:
        if not isinstance(body, str):
            raise HttpTargetError("endpoint returned JSON but no response_path is configured")
        return body
    value = body
    for token in parse_response_path(path):
        if isinstance(token, int):
            if not isinstance(value, list) or token >= len(value):
                raise HttpTargetError(f"response_path {path!r} not found in endpoint reply")
            value = value[token]
        else:
            if not isinstance(value, Mapping) or token not in value:
                raise HttpTargetError(f"response_path {path!r} not found in endpoint reply")
            value = value[token]
    if not isinstance(value, str):
        raise HttpTargetError(f"response_path {path!r} did not resolve to text")
    return value


def render_template(template: Any, values: Mapping[str, Any]) -> Any:
    """Substitute placeholders throughout a nested JSON template."""

    if isinstance(template, str):
        if template.strip() == MESSAGES_PLACEHOLDER:
            return values["messages"]

        def _fill(match: re.Match) -> str:
            value = values.get(match.group(1))
            return "" if value is None else str(value)

        return _PLACEHOLDER_RE.sub(_fill, template)
    if isinstance(template, Mapping):
        return {key: render_template(value, values) for key, value in template.items()}
    if isinstance(template, list):
        return [render_template(value, values) for value in template]
    return template


def _split_messages(messages: Any) -> tuple[Optional[str], str]:
    """Return ``(system_prompt, prompt)`` from a chat-completions message list."""

    if not isinstance(messages, (list, tuple)) or not messages:
        raise ValueError("http target request must include messages")
    system_prompt = None
    prompt = None
    for message in messages:
        if not isinstance(message, Mapping):
            raise ValueError("http target messages must be objects")
        role, content = message.get("role"), message.get("content")
        if role == "system" and isinstance(content, str):
            system_prompt = content
        elif role == "user" and isinstance(content, str):
            prompt = content  # the last user turn is the attack
    if prompt is None:
        raise ValueError("http target request has no user message to send")
    return system_prompt, prompt


class _HttpCompletions:
    def __init__(self, client: "HttpTargetClient"):
        self._client = client

    def create(self, **request: Any) -> SimpleNamespace:
        text = self._client.send(request)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text))])


class HttpTargetClient:
    """Drive a deployed agent's HTTP endpoint through the chat-completions shape.

    There is deliberately no ``models`` attribute: the scanner's model
    preflight skips clients without one, because a deployed agent does not
    advertise which model sits behind it.
    """

    def __init__(self, base_url: str, http: Mapping[str, Any], *,
                 api_key: Optional[str] = None, timeout: float = 60.0,
                 opener: Optional[Any] = None):
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("http target base_url must be an HTTP(S) URL")
        self.base_url = base_url
        self.settings = validate_http_block(http)
        self._api_key = api_key
        self._timeout = float(timeout)
        self._opener = opener or request.build_opener()
        self._shared_session = uuid.uuid4().hex
        self.chat = SimpleNamespace(completions=_HttpCompletions(self))

    # ---- request construction ------------------------------------------

    def build_request(self, chat_request: Mapping[str, Any]) -> tuple[dict, bytes]:
        """Return ``(headers, body)`` for one chat request. Pure; used by tests."""

        messages = chat_request.get("messages")
        system_prompt, prompt = _split_messages(messages)
        session_id = (self._shared_session if self.settings["session"] == "shared"
                      else uuid.uuid4().hex)
        values = {
            "prompt": prompt,
            "system_prompt": system_prompt,
            "model": chat_request.get("model"),
            "session_id": session_id,
            "messages": [dict(message) for message in messages],
        }
        body = render_template(self.settings["request_template"], values)
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain",
            "User-Agent": "agentprobe-http-target",
            **self.settings["headers"],
        }
        if self._api_key:
            scheme = self.settings["auth_scheme"]
            headers[self.settings["auth_header"]] = (
                f"{scheme} {self._api_key}" if scheme else self._api_key
            )
        return headers, json.dumps(body, ensure_ascii=False).encode("utf-8")

    # ---- transport -------------------------------------------------------

    def send(self, chat_request: Mapping[str, Any]) -> str:
        headers, body = self.build_request(chat_request)
        http_request = request.Request(
            self.base_url, data=body, headers=headers, method=self.settings["method"],
        )
        try:
            with self._opener.open(http_request, timeout=self._timeout) as response:
                status = getattr(response, "status", 200)
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
                content_type = response.headers.get("Content-Type", "")
        except error.HTTPError as exc:
            # Never echo the response body: it may quote our own auth header.
            raise HttpTargetError(
                f"endpoint returned HTTP {exc.code}", status=exc.code,
            ) from None
        except (error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError) as exc:
            raise HttpTargetError(f"endpoint unreachable: {sanitize_error(exc)}") from None
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise HttpTargetError("endpoint reply exceeded the 4 MiB limit", status=status)
        text = raw.decode("utf-8", errors="replace")
        path = self.settings["response_path"]
        if path is None and "json" not in content_type.lower():
            return text
        try:
            decoded = json.loads(text)
        except json.JSONDecodeError:
            if path is None:
                return text
            raise HttpTargetError("endpoint reply was not valid JSON", status=status) from None
        return extract_response_text(decoded, path)


def build_http_target(provider_config: Mapping[str, Any]) -> HttpTargetClient:
    """Construct the client from a validated ``target`` block."""

    key_env = provider_config.get("api_key_env")
    api_key = os.environ.get(key_env) if key_env else None
    if key_env and not api_key:
        raise ValueError(f"http target api_key_env {key_env!r} is set but the variable is empty")
    return HttpTargetClient(
        provider_config["base_url"],
        provider_config.get("http") or {},
        api_key=api_key,
        timeout=provider_config.get("timeout_seconds", 60),
    )
