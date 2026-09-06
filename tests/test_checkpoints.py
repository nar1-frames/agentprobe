import json

import pytest

import agentprobe_v11 as v11
from agentprobe.checkpoints import CheckpointError, ScanCheckpoint


def _library():
    return {
        "fixture": [
            {"prompt": "first", "severity": "LOW", "description": "one", "_library_index": 1},
            {"prompt": "second", "severity": "HIGH", "description": "two", "_library_index": 2},
        ]
    }


def _row(attack, response="response"):
    return (attack, response, "SAFE", None, "fixture", "keyword")


def test_checkpoint_is_private_atomic_and_resumes_exact_rows(tmp_path):
    path = tmp_path / "scan.checkpoint.json"
    library = _library()
    store = ScanCheckpoint(
        str(path), target_model="target-3b", judge_model="judge-8b",
        attack_library=library, run_metadata={"config_sha256": "a" * 64},
    )
    store.record("fixture", _row(library["fixture"][0]), 1)

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["status"] == "in_progress"
    assert len(payload["results"]) == 1
    assert path.stat().st_mode & 0o077 == 0

    resumed = ScanCheckpoint(
        str(path), target_model="target-3b", judge_model="judge-8b",
        attack_library=library, run_metadata={"config_sha256": "a" * 64},
        resume=True,
    )
    assert resumed.has("fixture:1")
    assert resumed.row("fixture:1")[0]["prompt"] == "first"
    resumed.record("fixture", _row(library["fixture"][1]), 2)
    resumed.finalize()
    assert json.loads(path.read_text(encoding="utf-8"))["status"] == "complete"

    rebuilt = ScanCheckpoint(
        str(path), target_model="target-3b", judge_model="judge-8b",
        attack_library=library, run_metadata={"config_sha256": "a" * 64},
        resume=True,
    )
    assert rebuilt.has("fixture:1") and rebuilt.has("fixture:2")


def test_checkpoint_refuses_different_scan_definition(tmp_path):
    path = tmp_path / "scan.checkpoint.json"
    library = _library()
    ScanCheckpoint(
        str(path), target_model="target-3b", judge_model="judge-8b",
        attack_library=library, run_metadata={"config_sha256": "a" * 64},
    )
    with pytest.raises(CheckpointError, match="target model"):
        ScanCheckpoint(
            str(path), target_model="target-8b", judge_model="judge-8b",
            attack_library=library, run_metadata={"config_sha256": "a" * 64},
            resume=True,
        )
    with pytest.raises(CheckpointError, match="run metadata"):
        ScanCheckpoint(
            str(path), target_model="target-3b", judge_model="judge-8b",
            attack_library=library, run_metadata={"config_sha256": "b" * 64},
            resume=True,
        )


def test_scan_checkpoint_survives_interrupt_and_skips_completed_attack(tmp_path, monkeypatch):
    library = _library()
    path = tmp_path / "scan.checkpoint.json"
    calls = []
    interrupted = {"value": True}

    def fake_send_prompt(*args, **kwargs):
        calls.append(args[2])
        if interrupted["value"] and len(calls) == 2:
            interrupted["value"] = False
            raise KeyboardInterrupt
        return "I cannot help with that request. I will not provide it."

    monkeypatch.setattr(v11, "send_prompt", fake_send_prompt)
    monkeypatch.setattr(v11.time, "sleep", lambda _seconds: None)

    with pytest.raises(KeyboardInterrupt):
        v11.run_full_scan(
            object(), "target-3b", object(), "judge-8b", library, 0,
            checkpoint_path=str(path), run_metadata={"config_sha256": "a" * 64},
        )

    partial = json.loads(path.read_text(encoding="utf-8"))
    assert partial["status"] == "in_progress"
    assert [row["attack_id"] for row in partial["results"]] == ["fixture:1"]

    results = v11.run_full_scan(
        object(), "target-3b", object(), "judge-8b", library, 0,
        checkpoint_path=str(path), resume=True,
        run_metadata={"config_sha256": "a" * 64},
    )
    assert len(results["fixture"]) == 2
    assert calls == ["first", "second", "second"]
    assert json.loads(path.read_text(encoding="utf-8"))["status"] == "complete"


def test_repair_errors_retries_only_failed_target_rows(tmp_path, monkeypatch):
    library = _library()
    path = tmp_path / "scan.checkpoint.json"
    calls = []
    first_attempt = {"value": True}

    def fake_send_prompt(*args, **kwargs):
        calls.append(args[2])
        if args[2] == "first" and first_attempt["value"]:
            first_attempt["value"] = False
            return "[ERROR: transient provider failure]"
        return "I cannot help with that request. I will not provide it."

    monkeypatch.setattr(v11, "send_prompt", fake_send_prompt)
    monkeypatch.setattr(v11.time, "sleep", lambda _seconds: None)
    v11.run_full_scan(
        object(), "target-3b", object(), "judge-8b", library, 0,
        checkpoint_path=str(path), run_metadata={"config_sha256": "a" * 64},
    )
    repaired = v11.run_full_scan(
        object(), "target-3b", object(), "judge-8b", library, 0,
        checkpoint_path=str(path), resume=True, repair_errors=True,
        run_metadata={"config_sha256": "a" * 64},
    )
    assert calls == ["first", "second", "first"]
    assert repaired["fixture"][0][5] == "keyword"
    assert json.loads(path.read_text(encoding="utf-8"))["status"] == "complete"


def test_repair_judge_error_reuses_frozen_target_response(tmp_path, monkeypatch):
    library_row = _library()["fixture"][0]
    library = {"fixture": [library_row]}
    path = tmp_path / "scan.checkpoint.json"
    target_calls = []
    judge_results = iter([
        ("SUSPICIOUS", "judge unavailable", "judge-error"),
        ("SAFE", "retry succeeded", "keyword"),
    ])

    monkeypatch.setattr(
        v11, "send_prompt",
        lambda *args, **kwargs: target_calls.append(args[2]) or "ambiguous response",
    )
    monkeypatch.setattr(v11, "assess_vulnerability", lambda *args, **kwargs: next(judge_results))
    monkeypatch.setattr(v11.time, "sleep", lambda _seconds: None)

    v11.run_full_scan(
        object(), "target-3b", object(), "judge-8b", library, 0,
        checkpoint_path=str(path), run_metadata={"config_sha256": "b" * 64},
    )
    repaired = v11.run_full_scan(
        object(), "target-3b", object(), "judge-8b", library, 0,
        checkpoint_path=str(path), resume=True, repair_errors=True,
        run_metadata={"config_sha256": "b" * 64},
    )
    assert target_calls == [library_row["prompt"]]
    assert repaired["fixture"][0][1] == "ambiguous response"
    assert repaired["fixture"][0][5] == "keyword"
