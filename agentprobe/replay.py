"""Deterministic record/replay of chat-completion requests for offline scans.

A recording maps the SHA-256 of each canonical request to the text content the
provider returned for it. :class:`RecordingClient` writes one while forwarding a
real run; :class:`ReplayClient` serves it back with no network access. Replay
never fabricates: a request without a recorded entry raises :class:`ReplayMiss`,
which the scanner records as an operational error rather than a verdict.

Requests carry only the model, messages, and generation settings, never
credentials. Recordings do hold raw prompts and model output, so they are
written privately and kept out of version control.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from types import SimpleNamespace
from typing import Any, Dict, Mapping, Union

from agentprobe.reporting import _write_json_atomic


REPLAY_SCHEMA_VERSION = "1.0"
_REQUIRED_FIELDS = ("model", "messages", "max_tokens", "temperature")
_OPTIONAL_FIELDS = ("reasoning_effort",)


class ReplayMiss(ValueError):
    """Raised when a replayed request has no recorded response."""


def canonical_request(request: Mapping[str, Any]) -> Dict[str, Any]:
    """Return the replay-relevant request fields, rejecting anything else.

    Unknown fields (for example tool schemas) are refused rather than ignored,
    so two requests that a provider would treat differently never share a
    digest.
    """

    if not isinstance(request, Mapping):
        raise ValueError("replay request must be a mapping")
    unknown = sorted(set(request) - set(_REQUIRED_FIELDS) - set(_OPTIONAL_FIELDS))
    if unknown:
        raise ValueError(f"replay does not support request fields: {unknown}")
    missing = [key for key in _REQUIRED_FIELDS if key not in request]
    if missing:
        raise ValueError(f"replay request is missing fields: {missing}")
    model = request["model"]
    if not isinstance(model, str) or not model.strip():
        raise ValueError("replay request model must be a non-empty string")
    messages = request["messages"]
    if not isinstance(messages, (list, tuple)) or not all(isinstance(m, Mapping) for m in messages):
        raise ValueError("replay request messages must be a list of objects")
    max_tokens = request["max_tokens"]
    if isinstance(max_tokens, bool) or not isinstance(max_tokens, int):
        raise ValueError("replay request max_tokens must be an integer")
    temperature = request["temperature"]
    if (isinstance(temperature, bool) or not isinstance(temperature, (int, float))
            or not math.isfinite(temperature)):
        raise ValueError("replay request temperature must be a finite number")
    canonical = {
        "model": model,
        "messages": [dict(message) for message in messages],
        "max_tokens": max_tokens,
        # 0 and 0.0 are the same provider request; keep them one digest.
        "temperature": float(temperature),
    }
    if request.get("reasoning_effort") is not None:
        canonical["reasoning_effort"] = request["reasoning_effort"]
    return canonical


def request_digest(request: Mapping[str, Any]) -> str:
    """Return the SHA-256 of the request's canonical JSON."""

    encoded = json.dumps(
        canonical_request(request), sort_keys=True, ensure_ascii=False, separators=(",", ":"),
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _completion(content: str) -> SimpleNamespace:
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])


def load_recording(path: str) -> Dict[str, Dict[str, Any]]:
    """Load and fully validate a recording, returning its entries."""

    if not isinstance(path, str) or not path.strip():
        raise ValueError("replay_path must be a non-empty file path")
    if not os.path.isfile(path):
        raise FileNotFoundError(f"replay recording not found: {path}")
    with open(path, encoding="utf-8") as handle:
        try:
            data = json.load(handle)
        except json.JSONDecodeError as exc:
            raise ValueError(f"replay recording is not valid JSON: {exc}") from exc
    if not isinstance(data, Mapping) or set(data) != {"schema_version", "entries"}:
        raise ValueError("replay recording must contain exactly schema_version and entries")
    if data["schema_version"] != REPLAY_SCHEMA_VERSION:
        raise ValueError(f"unsupported replay schema version: {data['schema_version']!r}")
    entries = data["entries"]
    if not isinstance(entries, Mapping):
        raise ValueError("replay recording entries must be an object")
    for digest, entry in entries.items():
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"replay entry key is not a SHA-256 digest: {digest!r}")
        if not isinstance(entry, Mapping) or set(entry) != {"request", "content"}:
            raise ValueError(f"replay entry {digest} must contain exactly request and content")
        if not isinstance(entry["content"], str):
            raise ValueError(f"replay entry {digest} content must be a string")
        try:
            actual = request_digest(entry["request"])
        except ValueError as exc:
            raise ValueError(f"replay entry {digest} has an invalid request: {exc}") from exc
        # A hand-edited request must not keep answering under its old digest.
        if actual != digest:
            raise ValueError(f"replay entry {digest} does not match its recorded request")
    return {digest: dict(entry) for digest, entry in entries.items()}


class _ReplayCompletions:
    def __init__(self, entries: Mapping[str, Mapping[str, Any]]):
        self._entries = entries

    def create(self, **request: Any) -> SimpleNamespace:
        digest = request_digest(request)
        entry = self._entries.get(digest)
        if entry is None:
            raise ReplayMiss(
                f"no recorded response for request {digest} (model {request['model']!r})"
            )
        return _completion(entry["content"])


class _ReplayModels:
    def __init__(self, entries: Mapping[str, Mapping[str, Any]]):
        self._models = sorted({entry["request"]["model"] for entry in entries.values()})

    def list(self) -> Dict[str, Any]:
        return {"data": [{"id": model} for model in self._models]}


class ReplayClient:
    """Serve recorded responses through the chat-completions client interface."""

    def __init__(self, path: str):
        self.path = path
        entries = load_recording(path)
        self.chat = SimpleNamespace(completions=_ReplayCompletions(entries))
        self.models = _ReplayModels(entries)


class ReplayRecording:
    """A recording file that one or more :class:`RecordingClient` share."""

    def __init__(self, path: str):
        if not isinstance(path, str) or not path.strip():
            raise ValueError("record_replay_path must be a non-empty file path")
        if os.path.exists(path):
            raise ValueError(f"replay recording already exists: {path}; choose a new path")
        self.path = path
        self.entries: Dict[str, Dict[str, Any]] = {}
        self._save()

    def record(self, request: Mapping[str, Any], content: str) -> None:
        digest = request_digest(request)
        # The first response for a request is the one replay will serve; a
        # scan never sends an identical request twice after a success.
        self.entries.setdefault(digest, {"request": canonical_request(request), "content": content})
        self._save()

    def _save(self) -> None:
        _write_json_atomic(
            self.path,
            {"schema_version": REPLAY_SCHEMA_VERSION, "entries": self.entries},
            ".agentprobe-replay-",
        )


class _RecordingCompletions:
    def __init__(self, inner: Any, recording: ReplayRecording):
        self._inner = inner
        self._recording = recording

    def create(self, **request: Any) -> Any:
        canonical_request(request)  # refuse unsupported requests before spending a call
        result = self._inner.chat.completions.create(**request)
        choices = getattr(result, "choices", None)
        content = getattr(getattr(choices[0], "message", None), "content", None) if choices else None
        # Responses without text are left unrecorded; the scanner treats them
        # as operational errors, and replay reports them as misses.
        if isinstance(content, str):
            self._recording.record(request, content)
        return result


class RecordingClient:
    """Forward requests to ``inner`` and record each successful text response."""

    def __init__(self, inner: Any, recording: Union[str, ReplayRecording]):
        if not isinstance(recording, ReplayRecording):
            recording = ReplayRecording(recording)
        self.inner = inner
        self.recording = recording
        self.chat = SimpleNamespace(completions=_RecordingCompletions(inner, recording))

    @property
    def models(self) -> Any:
        return getattr(self.inner, "models", None)
