"""The closed, versioned vocabulary of harness trace events.

Every event a harness runtime records is built by :func:`make_event`, so the
trace a reviewer reads in harness JSON uses only the names, fields, and field
types registered here. Each event carries a ``layer`` naming the part of the
agent stack that produced it: the model, a tool request, the policy gate, tool
execution, or retrieved content.

The registry formalizes the events the runtimes already emitted; it does not
rename them. ``source`` is not used as the layer key because the
``untrusted_content_retrieved`` event already uses it for the content origin.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Sequence


EVENT_SCHEMA_VERSION = "1.0"
EVENT_LAYERS = frozenset({"model", "tool", "policy", "execution", "content"})

# Field order here is the order fields appear in a serialized event.
EVENT_TYPES: Dict[str, Dict[str, Any]] = {
    "model_error": {"layer": "model", "required": ("error",), "optional": ()},
    "provider_error": {"layer": "model", "required": ("error",), "optional": ()},
    "message_malformed": {"layer": "model", "required": ("reason",), "optional": ()},
    "tool_requested": {"layer": "tool", "required": ("call",), "optional": ()},
    "tool_malformed": {"layer": "tool", "required": ("call", "reason"), "optional": ()},
    "tool_blocked": {"layer": "policy", "required": ("call", "reason"), "optional": ()},
    "tool_executed": {"layer": "execution", "required": ("call",), "optional": ()},
    "tool_error": {"layer": "execution", "required": ("call", "error"), "optional": ()},
    "tool_executor_error": {"layer": "execution", "required": ("error",), "optional": ()},
    "untrusted_content_retrieved": {
        "layer": "content", "required": ("source", "tool_call_id"), "optional": (),
    },
}

_FIELD_TYPES = {
    "call": Mapping,
    "reason": str,
    "error": str,
    "source": str,
    "tool_call_id": str,
}
_ENVELOPE = ("step", "event", "layer")


def _check_fields(name: str, step: Any, fields: Mapping[str, Any]) -> Dict[str, Any]:
    spec = EVENT_TYPES.get(name) if isinstance(name, str) else None
    if spec is None:
        raise ValueError(f"unknown event type: {name!r}")
    # -1 is reserved for events recorded before the first model step, such as
    # retrieved content that is already in the conversation.
    if isinstance(step, bool) or not isinstance(step, int) or step < -1:
        raise ValueError(f"{name} step must be an integer >= -1, not {step!r}")
    missing = [key for key in spec["required"] if key not in fields]
    if missing:
        raise ValueError(f"{name} is missing required fields: {missing}")
    allowed = spec["required"] + spec["optional"]
    unknown = sorted(key for key in fields if key not in allowed)
    if unknown:
        raise ValueError(f"{name} has unknown fields: {unknown}")
    for key in allowed:
        if key in fields and not isinstance(fields[key], _FIELD_TYPES[key]):
            raise ValueError(f"{name} field {key!r} must be {_FIELD_TYPES[key].__name__}")
    event = {"step": step, "event": name, "layer": spec["layer"]}
    event.update((key, fields[key]) for key in allowed if key in fields)
    return event


def make_event(name: str, step: int, **fields: Any) -> Dict[str, Any]:
    """Return a validated event with keys ordered step, event, layer, fields."""

    return _check_fields(name, step, fields)


def validate_event(event: Any) -> None:
    """Raise ValueError unless ``event`` is a well-formed registered event."""

    if not isinstance(event, Mapping):
        raise ValueError("event must be a mapping")
    missing = [key for key in _ENVELOPE if key not in event]
    if missing:
        raise ValueError(f"event is missing envelope fields: {missing}")
    expected = _check_fields(
        event["event"], event["step"],
        {key: value for key, value in event.items() if key not in _ENVELOPE},
    )
    if event["layer"] != expected["layer"]:
        raise ValueError(
            f"{event['event']} layer must be {expected['layer']!r}, not {event['layer']!r}"
        )


def validate_events(events: Sequence[Any]) -> None:
    """Validate a trace, naming the index of the first malformed event."""

    if not isinstance(events, Sequence) or isinstance(events, (str, bytes)):
        raise ValueError("events must be a list")
    for index, event in enumerate(events):
        try:
            validate_event(event)
        except ValueError as exc:
            raise ValueError(f"event {index}: {exc}") from exc
