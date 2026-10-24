import json
import os
import re
from types import SimpleNamespace
import pytest

from agentprobe.reporting import (
    build_harness_provenance, build_harness_report, build_json_report, build_run_metadata,
    safe_filename_component, save_harness_report, save_json_report,
)
from agentprobe.html_report import build_summary, generate_html_report, save_html_report
from agentprobe.legacy import v11
from agentprobe import interactive as v12
from agentprobe.models import parse_model_size_b, validate_judge_strength


def _rows():
    attack = {"prompt": "attack", "severity": "HIGH", "description": "test"}
    return {
        "jailbreak": [
            (attack, "complied", "VULNERABLE", "HIGH", "judge said so", "llm-judge"),
            (attack, "failed", "SUSPICIOUS", None, "timeout", "target-error"),
        ]
    }


def test_json_report_has_stable_summary_and_error_boundary():
    report = build_json_report(_rows(), "target-model", "judge-model", generated_at="fixed")
    assert report["schema_version"] == "1.0"
    assert report["generated_at"] == "fixed"
    assert report["summary"]["total_attacks"] == 2
    assert report["summary"]["scorable_attacks"] == 1
    assert report["summary"]["verdicts"]["VULNERABLE"] == 1
    assert report["summary"]["operational_errors"] == 1
    assert report["categories"]["jailbreak"]["operational_errors"] == 1
    assert report["results"][1]["status"] == "error"
    assert report["results"][1]["finding_severity"] is None


def test_harness_report_is_versioned_summarized_and_private(tmp_path):
    report = build_harness_report([
        {
            "scenario_kind": "attack", "attack_succeeded": True,
            "operational_errors": [],
        },
        {
            "scenario_kind": "control", "control_succeeded": True,
            "operational_errors": ["fixture warning"],
        },
    ], "guarded", generated_at="fixed")
    assert report["artifact_type"] == "agentprobe_harness"
    assert report["summary"] == {
        "scenarios": 2, "attacks": 1, "attack_successes": 1,
        "controls": 1, "controls_passed": 1, "operational_errors": 1,
    }
    path = save_harness_report(report, str(tmp_path / "harness.json"))
    saved = json.loads(__import__("pathlib").Path(path).read_text())
    assert saved["schema_version"] == "1.4"
    assert saved["event_schema_version"] == "1.0"
    if os.name != "nt":  # NTFS has no POSIX mode bits; chmod cannot express 0o600.
        assert __import__("pathlib").Path(path).stat().st_mode & 0o077 == 0


def test_json_report_preserves_library_index_after_filtering():
    attack = {
        "prompt": "filtered attack", "severity": "CRITICAL",
        "description": "test", "_library_index": 7,
    }
    report = build_json_report(
        {"jailbreak": [(attack, "response", "SAFE", None, "ok", "keyword")]},
        "target-model", "judge-model", generated_at="fixed",
    )
    assert report["results"][0]["attack_index"] == 7
    assert report["results"][0]["attack_id"] == "jailbreak:7"


def test_runtime_attack_index_metadata_does_not_change_attack_digest():
    plain = {"jailbreak": [{"prompt": "attack", "severity": "HIGH"}]}
    indexed = {"jailbreak": [dict(plain["jailbreak"][0], _library_index=3)]}
    plain_meta = build_run_metadata("target", "judge", attack_library=plain)
    indexed_meta = build_run_metadata("target", "judge", attack_library=indexed)
    assert indexed_meta["attack_library_sha256"] == plain_meta["attack_library_sha256"]


def test_json_report_can_be_saved(tmp_path):
    report = build_json_report(_rows(), "target/model", "judge", generated_at="fixed")
    path = save_json_report(report, "target/model", str(tmp_path))
    with open(path, encoding="utf-8") as f:
        saved = json.load(f)
    assert saved["target_model"] == "target/model"
    assert saved["results"][0]["attack_id"] == "jailbreak:1"
    assert "T" in str(path)


def test_report_filename_cannot_escape_report_directory(tmp_path):
    assert safe_filename_component("../../evil\\model") == "evil_model"
    report = build_json_report(_rows(), "../../evil\\model", "judge", generated_at="fixed")
    path = save_json_report(report, "../../evil\\model", str(tmp_path))
    assert tmp_path == __import__("pathlib").Path(path).parent


def test_json_report_carries_run_provenance_and_unique_artifact_id(tmp_path):
    metadata = build_run_metadata(
        "target-model", "judge-model", target_provider="ollama",
        judge_provider="ollama", config={"scan": {"rate_limit_seconds": 0}},
        attack_library={"jailbreak": [{"prompt": "attack"}]}, run_id="run-12345678",
    )
    report = build_json_report(_rows(), "target-model", "judge-model", metadata=metadata)
    assert report["run"]["run_id"] == "run-12345678"
    assert report["run"]["target_provider"] == "ollama"
    assert len(report["run"]["config_sha256"]) == 64
    first = save_json_report(report, "target-model", str(tmp_path))
    second = save_json_report(report, "target-model", str(tmp_path))
    assert first == second  # same run id is intentionally idempotent


def test_run_metadata_exposes_behavioral_generation_settings_without_secrets():
    metadata = build_run_metadata(
        "target", "judge", config={
            "target": {"temperature": 0.0, "max_tokens": 512,
                       "api_key_env": "GROQ_API_KEY"},
            "judge": {"temperature": 0.7, "max_tokens": 120},
            "scan": {"retries": 2, "retry_delay_seconds": 3,
                     "rate_limit_seconds": 1},
        },
    )
    assert metadata["target_temperature"] == 0.0
    assert metadata["judge_temperature"] == 0.7
    assert metadata["target_max_tokens"] == 512
    assert metadata["scan_retries"] == 2
    assert "GROQ_API_KEY" not in metadata


def test_run_metadata_pins_judge_prompt_provenance():
    metadata = build_run_metadata(
        "target", "judge", judge_prompt_version="2.0",
        judge_prompt_sha256="a" * 64,
    )
    assert metadata["judge_prompt_version"] == "2.0"
    assert metadata["judge_prompt_sha256"] == "a" * 64


def test_harness_provenance_identifies_live_run_without_system_prompt():
    metadata = build_harness_provenance(
        "target-3b", provider="ollama", temperature=0.0, max_steps=4,
        max_tokens=256,
        system_prompt="private prompt", config={
            "provider": "ollama", "model": "target-3b", "api_key_env": None,
            "max_tokens": 256, "temperature": 0.0,
        },
    )
    assert metadata["target_model"] == "target-3b"
    assert metadata["target_provider"] == "ollama"
    assert metadata["max_steps"] == 4
    assert metadata["target_max_tokens"] == 256
    assert len(metadata["target_config_sha256"]) == 64
    assert len(metadata["system_prompt_sha256"]) == 64
    assert "private prompt" not in metadata


def test_interactive_picker_binds_selected_models_into_provenance_config():
    config = {
        "target": {"provider": "ollama", "model": "old-target",
                    "api_key_env": None, "temperature": 0.0},
        "judge": {"provider": "ollama", "model": "old-judge",
                   "api_key_env": None, "temperature": 0.1},
        "scan": {"categories": "all"},
    }
    selected = v12._selected_run_config(
        config,
        {"provider": "groq", "model": "picked-target",
         "api_key_env": "GROQ_API_KEY", "base_url": None},
        {"provider": "openai", "model": "picked-judge",
         "api_key_env": "OPENAI_API_KEY", "base_url": None},
    )
    assert selected["target"]["model"] == "picked-target"
    assert selected["target"]["provider"] == "groq"
    assert selected["judge"]["model"] == "picked-judge"
    assert selected["judge"]["provider"] == "openai"
    assert config["target"]["model"] == "old-target"


def test_report_filenames_sanitize_supplied_run_ids(tmp_path):
    report = build_json_report(
        _rows(), "target", "judge", generated_at="fixed",
        metadata={"run_id": "../../escape"},
    )
    path = save_json_report(report, "target", str(tmp_path))
    assert __import__("pathlib").Path(path).parent == tmp_path
    assert "escape" in __import__("pathlib").Path(path).name


def test_target_failure_is_not_sent_to_the_judge(monkeypatch):
    class ExplodingJudge:
        def __getattr__(self, _name):
            raise AssertionError("failed target output must not reach the judge")

    attack = {"prompt": "attack", "severity": "HIGH", "description": "test"}
    monkeypatch.setattr(v11, "send_prompt", lambda *args, **kwargs: "[ERROR: timeout]")
    results = v11.run_full_scan(
        object(), "target", ExplodingJudge(), "judge", {"jailbreak": [attack]}, 0,
    )
    row = results["jailbreak"][0]
    assert row[2] == "SUSPICIOUS"
    assert row[3] is None
    assert row[5] == "target-error"


def test_offline_scan_integration_routes_keyword_and_judge_paths(monkeypatch):
    class FakeClient:
        def __init__(self, responses):
            self.responses = iter(responses)
            self.calls = []

            outer = self
            class Completions:
                def create(self, **kwargs):
                    outer.calls.append(kwargs)
                    return SimpleNamespace(
                        choices=[SimpleNamespace(
                            message=SimpleNamespace(content=next(outer.responses))
                        )]
                    )

            self.chat = SimpleNamespace(completions=Completions())

    target = FakeClient([
        "I can't help with that and I won't provide it.",
        "Sure, as requested, here is the answer.",
    ])
    judge = FakeClient(["VERDICT: COMPLIED\nREASON: fixture judge"])
    attacks = {
        "jailbreak": [
            {"prompt": "first", "severity": "HIGH", "description": "one",
             "_library_index": 2},
            {"prompt": "second", "severity": "HIGH", "description": "two",
             "_library_index": 7},
        ],
    }
    monkeypatch.setattr(v11.time, "sleep", lambda *_args: None)
    results = v11.run_full_scan(
        target, "target-3b", judge, "judge-8b", attacks, 0,
        max_tokens=64, retries=0, retry_delay=0,
        target_temperature=0.2,
        judge_temperature=0.7, judge_max_tokens=32,
    )
    rows = results["jailbreak"]
    assert [row[2] for row in rows] == ["SAFE", "VULNERABLE"]
    assert [row[5] for row in rows] == ["keyword", "llm-judge"]
    assert len(target.calls) == 2
    assert all(call["temperature"] == 0.2 for call in target.calls)
    assert len(judge.calls) == 1
    assert judge.calls[0]["temperature"] == 0.7
    assert judge.calls[0]["max_tokens"] == 32
    report = build_json_report(results, "target-3b", "judge-8b", generated_at="fixed")
    assert [row["attack_id"] for row in report["results"]] == ["jailbreak:2", "jailbreak:7"]


def test_empty_provider_message_becomes_target_error(monkeypatch):
    class EmptyTarget:
        class chat:
            class completions:
                @staticmethod
                def create(**_kwargs):
                    class Message:
                        content = EmptyTarget.content
                    class Choice:
                        message = Message()
                    class Result:
                        choices = [Choice()]
                    return Result()

    monkeypatch.setattr(v11.time, "sleep", lambda *_args: None)
    for content in (None, "   "):
        EmptyTarget.content = content
        response = v11.send_prompt(EmptyTarget(), "target", "attack", retries=0)
        assert response.startswith("[ERROR:")
        assert "no text content" in response


def test_permanent_target_error_is_not_retried(monkeypatch):
    class AuthFailure(Exception):
        status_code = 401

    class FailingTarget:
        calls = 0

        class chat:
            class completions:
                @staticmethod
                def create(**_kwargs):
                    FailingTarget.calls += 1
                    raise AuthFailure("invalid credentials")

    monkeypatch.setattr(v11.time, "sleep", lambda *_args: None)
    response = v11.send_prompt(FailingTarget(), "target", "attack", retries=3)
    assert FailingTarget.calls == 1
    assert response.startswith("[ERROR:")


def test_configured_scan_entry_point_is_importable():
    assert callable(v11.run_configured_scan)


def test_configured_scan_strength_rule_fails_closed(monkeypatch):
    monkeypatch.setattr(v11, "load_config", lambda _path: {
        "target": {"model": "target-14b"},
        "judge": {"model": "judge-8b"},
    })
    with pytest.raises(ValueError, match="smaller than target"):
        v11.run_configured_scan("fixture.yaml")


def test_configured_scan_writes_html_and_json_with_shared_run_id(tmp_path, monkeypatch):
    config = {
        "target": {
            "provider": "ollama", "model": "target-3b", "max_tokens": 64,
            "timeout_seconds": 10, "temperature": 0.2,
        },
        "judge": {
            "provider": "ollama", "model": "judge-8b", "timeout_seconds": 10,
            "temperature": 0.7, "max_tokens": 256,
        },
        "scan": {"categories": ["jailbreak"], "rate_limit_seconds": 0,
                 "retries": 0, "retry_delay_seconds": 0},
        "output": {"report_dir": str(tmp_path), "report_format": "both"},
    }
    monkeypatch.setattr(v11, "load_config", lambda _path: config)
    monkeypatch.setattr(v11, "build_client", lambda _cfg: object())
    captured = {}
    def fake_run_full_scan(*_args, **kwargs):
        captured.update(kwargs)
        return _rows()
    monkeypatch.setattr(v11, "run_full_scan", fake_run_full_scan)

    run = v11.run_configured_scan("fixture.yaml")
    assert run["html_path"] and run["json_path"]
    with open(run["json_path"], encoding="utf-8") as f:
        report = json.load(f)
    run_id = report["run"]["run_id"]
    assert run_id
    assert run_id[:8] in run["html_path"]
    html = open(run["html_path"], encoding="utf-8").read()
    assert "AgentProbe" in html
    assert f'name="agentprobe-run-id" content="{run_id}"' in html
    assert captured["judge_temperature"] == 0.7
    assert captured["judge_max_tokens"] == 256
    assert captured["target_temperature"] == 0.2


def test_model_size_parser_and_unknown_strength_are_explicit():
    assert parse_model_size_b("llama3.1:8b") == 8.0
    with pytest.raises(ValueError, match="Cannot verify"):
        validate_judge_strength("target-model", "judge-model")
    assert validate_judge_strength(
        "target-model", "judge-model", {"strength_rank": 1}, {"strength_rank": 2}
    ) is True


def test_html_report_does_not_count_target_failure_as_a_finding():
    findings, total, safe, partial, vulnerable, total_findings, overall, errors = build_summary(_rows())
    assert total == 2
    assert total_findings == 1
    assert errors == 1
    assert len(findings["LOW"]) == 0
    html = generate_html_report(_rows(), "target", "judge")
    assert "1 operational request(s) failed and were excluded from findings." in html
    assert "1 of 1 scorable attack prompts" in html


def test_filtered_attack_numbers_and_html_provenance_are_auditable():
    filtered = v11.filter_attacks({
        "scan": {"categories": ["jailbreak"], "severity_filter": "CRITICAL"},
    })
    assert [attack["_library_index"] for attack in filtered["jailbreak"]] == [1, 2, 5, 7]
    html = generate_html_report(
        {"jailbreak": []}, "target", "judge",
        metadata={
            "run_id": "run-123", "tool_version": "1.3.0",
            "target_provider": "ollama", "judge_provider": "ollama",
            "config_sha256": "c" * 64, "attack_library_sha256": "a" * 64,
        },
    )
    assert 'name="agentprobe-run-id" content="run-123"' in html
    assert "0 prompts · 1 categories" in html
    assert 'name="agentprobe-config-sha256"' in html


def test_html_report_filename_matches_the_json_report_shape(tmp_path):
    html_path = save_html_report("<html></html>", "openai/gpt-oss-20b", str(tmp_path),
                                 run_id="abcdef123456")
    json_path = save_json_report(
        build_json_report(_rows(), "openai/gpt-oss-20b", "judge",
                          metadata={"run_id": "abcdef123456"}),
        "openai/gpt-oss-20b", str(tmp_path),
    )
    pattern = r"scan_openai_gpt-oss-20b_\d{8}T\d{6}Z_abcdef12\.%s"
    assert "_v11_" not in os.path.basename(html_path)
    assert re.fullmatch(pattern % "html", os.path.basename(html_path))
    assert re.fullmatch(pattern % "json", os.path.basename(json_path))
