import json
import os
import socket
from types import SimpleNamespace

import pytest
import yaml

from agentprobe import scanner
from agentprobe.config import validate_config
from agentprobe.providers import build_client, preflight_model, requires_external_consent
from agentprobe.replay import (
    REPLAY_SCHEMA_VERSION,
    RecordingClient,
    ReplayClient,
    ReplayMiss,
    ReplayRecording,
    request_digest,
)


def _request(prompt="attack", model="fixture-target", **extra):
    return {
        "messages": [{"role": "user", "content": prompt}],
        "model": model,
        "max_tokens": 64,
        "temperature": 0.0,
        **extra,
    }


class _FakeProvider:
    """Deterministic stand-in for a live provider: refuses some prompts, not others."""

    def __init__(self):
        self.calls = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **request):
        self.calls.append(request)
        if request["model"] == "fixture-judge":
            content = "VERDICT: COMPLIED\nREASON: fixture judge"
        elif len(request["messages"][-1]["content"]) % 2:
            content = "I can't help with that and I won't provide it."
        else:
            content = "Sure, as requested, here is the answer."
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])


def test_request_digest_is_canonical_and_rejects_unsupported_fields():
    reordered = dict(reversed(list(_request().items())))
    assert request_digest(_request()) == request_digest(reordered)
    assert request_digest(_request()) == request_digest({**_request(), "temperature": 0})
    assert request_digest(_request()) == request_digest(_request(reasoning_effort=None))
    assert request_digest(_request()) != request_digest(_request(reasoning_effort="low"))
    assert request_digest(_request()) != request_digest(_request("other attack"))
    with pytest.raises(ValueError, match=r"does not support request fields: \['tools'\]"):
        request_digest(_request(tools=[]))


def test_recording_round_trips_and_replay_never_fabricates(tmp_path):
    path = str(tmp_path / "scan.replay.json")
    provider = _FakeProvider()
    recorder = RecordingClient(provider, path)
    assert json.loads(open(path, encoding="utf-8").read()) == {
        "schema_version": REPLAY_SCHEMA_VERSION, "entries": {},
    }
    recorded = recorder.chat.completions.create(**_request("odd"))
    recorder.chat.completions.create(**_request("even"))
    assert len(json.loads(open(path, encoding="utf-8").read())["entries"]) == 2
    assert os.listdir(tmp_path) == ["scan.replay.json"]

    replay = ReplayClient(path)
    replayed = replay.chat.completions.create(**_request("odd"))
    assert replayed.choices[0].message.content == recorded.choices[0].message.content
    assert replay.models.list() == {"data": [{"id": "fixture-target"}]}
    assert preflight_model(replay, "fixture-target") is True
    with pytest.raises(ReplayMiss, match=r"no recorded response for request [0-9a-f]{64} \(model 'fixture-target'\)"):
        replay.chat.completions.create(**_request("never recorded"))
    assert len(provider.calls) == 2


def test_recording_skips_provider_errors_and_refuses_to_overwrite(tmp_path):
    class Failing:
        chat = SimpleNamespace(completions=SimpleNamespace(
            create=lambda **_request: (_ for _ in ()).throw(TimeoutError("provider timeout"))
        ))

    path = str(tmp_path / "scan.replay.json")
    with pytest.raises(TimeoutError):
        RecordingClient(Failing(), path).chat.completions.create(**_request())
    assert json.loads(open(path, encoding="utf-8").read())["entries"] == {}
    with pytest.raises(ValueError, match="already exists"):
        ReplayRecording(path)


def test_replay_validates_the_recording_at_construction(tmp_path):
    with pytest.raises(FileNotFoundError):
        ReplayClient(str(tmp_path / "missing.replay.json"))

    path = tmp_path / "scan.replay.json"
    RecordingClient(_FakeProvider(), str(path)).chat.completions.create(**_request())
    data = json.loads(path.read_text(encoding="utf-8"))
    entry = next(iter(data["entries"].values()))

    entry["request"]["messages"][0]["content"] = "edited after recording"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="does not match its recorded request"):
        ReplayClient(str(path))

    path.write_text(json.dumps({**data, "schema_version": "0.9"}), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported replay schema version"):
        ReplayClient(str(path))


def test_replay_provider_config_and_consent():
    base = {
        "target": {"provider": "replay", "model": "fixture-target", "replay_path": "a.replay.json"},
        "judge": {"provider": "replay", "model": "fixture-judge", "replay_path": "a.replay.json"},
    }
    assert validate_config(base)["target"]["provider"] == "replay"
    assert requires_external_consent("replay") is False
    with pytest.raises(ValueError, match="target.replay_path is required"):
        validate_config({**base, "target": {"provider": "replay", "model": "fixture-target"}})
    with pytest.raises(ValueError, match="only valid with the replay provider"):
        validate_config({**base, "judge": {
            "provider": "ollama", "model": "fixture-judge", "replay_path": "a.replay.json",
        }})
    with pytest.raises(ValueError, match="record_replay_path must be a non-empty path"):
        validate_config({**base, "scan": {"record_replay_path": ""}})
    with pytest.raises(FileNotFoundError):
        build_client(base["target"])


def _write_config(path, target, judge, scan, report_dir):
    config = {
        "target": {"model": "fixture-target", "strength_rank": 1, "max_tokens": 64,
                   "temperature": 0.0, **target},
        "judge": {"model": "fixture-judge", "strength_rank": 2, "max_tokens": 32,
                  "temperature": 0.0, **judge},
        "scan": {"categories": ["jailbreak", "tool_misuse"], "rate_limit_seconds": 0,
                 "retries": 0, "retry_delay_seconds": 0, **scan},
        "output": {"report_dir": str(report_dir), "report_format": "json"},
    }
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return str(path)


def _rows(json_path):
    with open(json_path, encoding="utf-8") as f:
        report = json.load(f)
    rows = [(row["attack_id"], row["response"], row["verdict"], row["method"])
            for row in report["results"]]
    return report, rows


def test_recorded_scan_replays_offline_with_identical_results(tmp_path, monkeypatch):
    recording = tmp_path / "scan.replay.json"
    provider = _FakeProvider()
    monkeypatch.setattr(scanner, "build_client", lambda _config: provider)
    recorded_run = scanner.run_configured_scan(_write_config(
        tmp_path / "record.yaml", {"provider": "ollama"}, {"provider": "ollama"},
        {"record_replay_path": str(recording)}, tmp_path / "recorded",
    ))
    _, recorded_rows = _rows(recorded_run["json_path"])
    provider_calls = len(provider.calls)

    monkeypatch.setattr(scanner, "build_client", build_client)

    def no_network(*_args, **_kwargs):
        raise AssertionError("replay must not open a network connection")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    replay = {"provider": "replay", "replay_path": str(recording)}
    replayed_run = scanner.run_configured_scan(_write_config(
        tmp_path / "replay.yaml", replay, replay, {}, tmp_path / "replayed",
    ))
    report, replayed_rows = _rows(replayed_run["json_path"])

    assert len(replayed_rows) == 13
    assert replayed_rows == recorded_rows
    methods = {row[3] for row in replayed_rows}
    assert {"keyword", "llm-judge"} <= methods
    assert not methods & {"target-error", "judge-error"}
    assert report["run"]["target_provider"] == "replay"
    assert report["run"]["judge_provider"] == "replay"
    assert len(provider.calls) == provider_calls
