import pytest

from agentprobe.events import (
    EVENT_LAYERS,
    EVENT_SCHEMA_VERSION,
    EVENT_TYPES,
    make_event,
    validate_event,
    validate_events,
)
from agentprobe.harness import SCENARIOS, run_fixture_suite, run_scenario
from agentprobe.reporting import build_harness_report


_CALL = {"name": "read_file", "arguments": {}, "origin": "model"}


def test_registry_covers_exactly_the_harness_event_vocabulary():
    assert EVENT_SCHEMA_VERSION == "1.0"
    assert {name: spec["layer"] for name, spec in EVENT_TYPES.items()} == {
        "model_error": "model",
        "provider_error": "model",
        "message_malformed": "model",
        "tool_requested": "tool",
        "tool_malformed": "tool",
        "tool_blocked": "policy",
        "tool_executed": "execution",
        "tool_error": "execution",
        "tool_executor_error": "execution",
        "untrusted_content_retrieved": "content",
    }
    assert {spec["layer"] for spec in EVENT_TYPES.values()} == EVENT_LAYERS


def test_make_event_orders_keys_step_event_layer_then_fields():
    event = make_event("tool_blocked", 2, reason="tool is not allowlisted", call=_CALL)
    assert list(event) == ["step", "event", "layer", "call", "reason"]
    assert event == {
        "step": 2, "event": "tool_blocked", "layer": "policy",
        "call": _CALL, "reason": "tool is not allowlisted",
    }
    retrieved = make_event("untrusted_content_retrieved", -1, tool_call_id="id-1", source="doc")
    assert list(retrieved) == ["step", "event", "layer", "source", "tool_call_id"]


@pytest.mark.parametrize(("name", "step", "fields", "match"), [
    ("tool_teleported", 0, {"call": _CALL}, "unknown event type"),
    ("tool_blocked", 0, {"call": _CALL}, r"missing required fields: \['reason'\]"),
    ("tool_executed", 0, {"call": _CALL, "output": {}}, r"unknown fields: \['output'\]"),
    ("tool_executed", "0", {"call": _CALL}, "step must be an integer"),
    ("tool_executed", True, {"call": _CALL}, "step must be an integer"),
    ("tool_executed", -2, {"call": _CALL}, "step must be an integer >= -1"),
    ("tool_error", 0, {"call": _CALL, "error": 404}, "'error' must be str"),
    ("tool_requested", 0, {"call": "read_file"}, "'call' must be Mapping"),
])
def test_make_event_rejects_invalid_events(name, step, fields, match):
    with pytest.raises(ValueError, match=match):
        make_event(name, step, **fields)


def test_validate_event_rejects_missing_or_wrong_layer():
    event = make_event("tool_requested", 0, call=_CALL)
    with pytest.raises(ValueError, match="missing envelope fields"):
        validate_event({key: value for key, value in event.items() if key != "layer"})
    with pytest.raises(ValueError, match="layer must be 'tool', not 'policy'"):
        validate_event({**event, "layer": "policy"})


def test_validate_events_names_the_malformed_index():
    good = make_event("tool_requested", 0, call=_CALL)
    with pytest.raises(ValueError, match="event 2: unknown event type: 'tool_teleported'"):
        validate_events([good, good, {**good, "event": "tool_teleported"}])
    with pytest.raises(ValueError, match="events must be a list"):
        validate_events("not a trace")


@pytest.mark.parametrize("mode", ["guarded", "vulnerable", "model_only_guarded", "architecture_only_guarded"])
def test_fixture_suite_traces_conform_in_every_mode(mode):
    results = run_fixture_suite(mode)
    # A guarded model may request nothing for an injected scenario, so only
    # the suite as a whole is required to produce a trace.
    assert any(result.events for result in results)
    for result in results:
        validate_events(result.events)
        serialized = result.to_dict()["events"]
        validate_events(serialized)
        assert all(event["layer"] == EVENT_TYPES[event["event"]]["layer"] for event in serialized)


def test_serialization_refuses_a_malformed_trace():
    result = run_scenario(SCENARIOS[0], mode="guarded")
    result.events.append({"step": 9, "event": "tool_teleported", "layer": "tool"})
    with pytest.raises(ValueError, match=f"event {len(result.events) - 1}: unknown event type"):
        result.to_dict()

    report_row = {"scenario_kind": "attack", "events": [{"step": 0, "event": "tool_requested"}]}
    with pytest.raises(ValueError, match="invalid event trace: event 0"):
        build_harness_report([report_row], "guarded")
