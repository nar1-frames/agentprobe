import json
import xml.etree.ElementTree as ET

import pytest

from agentprobe import scanner
from agentprobe.attackpack import build_attack_pack
from agentprobe.cli import main
from agentprobe.exports import (
    harness_report_to_junit,
    harness_report_to_sarif,
    scan_report_to_junit,
    scan_report_to_sarif,
)
from agentprobe.harness import run_fixture_suite
from agentprobe.providers import build_client
from agentprobe.reporting import (
    TOOL_VERSION, build_harness_report, build_json_report, build_run_metadata,
)
from test_replay import _FakeProvider, _write_config


_ROWS = [
    ("VULNERABLE", "HIGH", "llm-judge"),
    ("PARTIAL", "MEDIUM", "llm-judge"),
    ("SUSPICIOUS", "LOW", "llm-judge"),
    ("SAFE", None, "keyword"),
    ("SUSPICIOUS", None, "target-error"),
    ("SUSPICIOUS", None, "judge-error"),
]
_EXPECTED_SARIF = [
    ("fail", "error", "VULNERABLE via llm-judge (finding severity HIGH)"),
    ("fail", "warning", "PARTIAL via llm-judge (finding severity MEDIUM)"),
    ("review", "none", "SUSPICIOUS via llm-judge; needs human review"),
    ("pass", "none", "SAFE via keyword"),
    ("open", "none", "operational error: target-error"),
    ("open", "none", "operational error: judge-error"),
]


def _scan_report():
    rows = []
    for index, (verdict, finding, method) in enumerate(_ROWS, start=1):
        attack = {"prompt": f"attack prompt {index}", "severity": "HIGH",
                  "description": f"what attack {index} tests", "_library_index": index}
        response = f"[ERROR: SENTINEL-RESPONSE-{index}]" if "error" in method else f"SENTINEL-RESPONSE-{index}"
        rows.append((attack, response, verdict, finding, f"SENTINEL-REASON-{index}", method))
    metadata = build_run_metadata("target-3b", "judge-8b", attack_library={"fixture": []},
                                  attack_pack=build_attack_pack(), run_id="run-fixture")
    return build_json_report({"fixture": rows[:3], "other": rows[3:]}, "target-3b", "judge-8b",
                             generated_at="fixed", metadata=metadata)


def _assert_junit_counts(xml_text):
    root = ET.fromstring(xml_text.split("\n", 1)[1])
    totals = dict.fromkeys(("tests", "failures", "errors", "skipped"), 0)
    for suite in root.findall("testsuite"):
        cases = suite.findall("testcase")
        counts = {
            "tests": len(cases),
            "failures": sum(case.find("failure") is not None for case in cases),
            "errors": sum(case.find("error") is not None for case in cases),
            "skipped": sum(case.find("skipped") is not None for case in cases),
        }
        assert {key: int(suite.get(key)) for key in counts} == counts
        for key, value in counts.items():
            totals[key] += value
    assert {key: int(root.get(key)) for key in totals} == totals
    return root, totals


def test_scan_sarif_maps_every_verdict_and_never_copies_responses_or_reasons():
    sarif = scan_report_to_sarif(_scan_report())
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert run["tool"]["driver"]["name"] == "agentprobe"
    assert len(run["tool"]["driver"]["rules"]) == 6
    assert [(r["kind"], r["level"], r["message"]["text"]) for r in run["results"]] == _EXPECTED_SARIF
    # SARIF 2.1.0 §3.27.9: only fail results may carry a non-"none" level.
    assert all(r["level"] == "none" for r in run["results"] if r["kind"] != "fail")
    assert run["results"][0]["locations"][0]["logicalLocations"][0] == {
        "name": "fixture:1", "kind": "attack", "fullyQualifiedName": "fixture/fixture:1",
    }
    assert run["invocations"] == [{"executionSuccessful": False}]
    assert run["properties"]["run_id"] == "run-fixture"
    assert len(run["properties"]["attack_pack_sha256"]) == 64
    text = json.dumps(sarif)
    assert "SENTINEL-RESPONSE" not in text and "SENTINEL-REASON" not in text


def test_scan_junit_counts_match_children_and_stay_data_minimized():
    xml_text = scan_report_to_junit(_scan_report())
    assert xml_text.startswith('<?xml version="1.0" encoding="UTF-8"?>\n')
    root, totals = _assert_junit_counts(xml_text)
    assert root.get("name") == "agentprobe-scan"
    assert totals == {"tests": 6, "failures": 2, "errors": 2, "skipped": 1}
    failure = root.find(".//testcase[@name='fixture:1']/failure")
    assert failure.get("type") == "VULNERABLE" and failure.get("message") == "HIGH via llm-judge"
    assert root.find(".//testcase[@name='other:5']/error").get("type") == "target-error"
    suite_properties = {p.get("name"): p.get("value") for p in root.find("testsuite").iter("property")}
    assert suite_properties == {
        "run_id": "run-fixture", "target_model": "target-3b",
        "judge_model": "judge-8b", "tool_version": TOOL_VERSION,
    }
    assert "SENTINEL-RESPONSE" not in xml_text and "SENTINEL-REASON" not in xml_text


@pytest.mark.parametrize(("mode", "expect_failures"), [("guarded", False), ("vulnerable", True)])
def test_harness_exports_reflect_attack_outcomes(mode, expect_failures):
    report = build_harness_report(run_fixture_suite(mode), mode)
    sarif = harness_report_to_sarif(report)
    run = sarif["runs"][0]
    failed = [r for r in run["results"] if r["kind"] == "fail"]
    assert bool(failed) is expect_failures
    assert run["properties"]["mode"] == mode
    assert run["properties"]["event_schema_version"] == "1.0"
    _, totals = _assert_junit_counts(harness_report_to_junit(report))
    assert (totals["failures"] > 0) is expect_failures
    for exported in (json.dumps(sarif), harness_report_to_junit(report)):
        assert "FIXTURE_SECRET_DO_NOT_EXFILTRATE" not in exported
        assert "attacker@example.test" not in exported


def test_harness_operational_errors_are_reported_without_their_text():
    report = build_harness_report([{
        "attack_id": "fixture-attack", "category": "fixture", "scenario_kind": "attack",
        "attack_succeeded": False, "operational_errors": ["SENTINEL-ERROR one", "SENTINEL-ERROR two"],
    }], "live:guarded")
    run = harness_report_to_sarif(report)["runs"][0]
    assert [(r["kind"], r["message"]["text"]) for r in run["results"]] == [
        ("pass", "attack blocked"), ("open", "operational errors: 2"),
    ]
    xml_text = harness_report_to_junit(report)
    root, totals = _assert_junit_counts(xml_text)
    assert totals["errors"] == 1
    assert root.find(".//error").get("message") == "2 operational error(s)"
    assert "SENTINEL-ERROR" not in json.dumps(run) and "SENTINEL-ERROR" not in xml_text


def test_harness_cli_writes_both_exports_and_keeps_stdout_json_clean(tmp_path, capsys):
    sarif_path, junit_path = tmp_path / "harness.sarif", tmp_path / "harness.junit.xml"
    assert main(["harness", "--mode", "guarded", "--sarif", str(sarif_path),
                 "--junit", str(junit_path), "--json", "-"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["artifact_type"] == "agentprobe_harness"
    assert "SARIF report saved to" in captured.err
    assert json.loads(sarif_path.read_text(encoding="utf-8"))["version"] == "2.1.0"
    _assert_junit_counts(junit_path.read_text(encoding="utf-8"))


def test_scan_exports_require_non_interactive():
    with pytest.raises(SystemExit):
        main(["scan", "--sarif", "out.sarif"])


def test_replayed_scan_cli_writes_sarif_and_junit(tmp_path, monkeypatch):
    recording = tmp_path / "scan.replay.json"
    monkeypatch.setattr(scanner, "build_client", lambda _config: _FakeProvider())
    scanner.run_configured_scan(_write_config(
        tmp_path / "record.yaml", {"provider": "ollama"}, {"provider": "ollama"},
        {"record_replay_path": str(recording)}, tmp_path / "recorded",
    ))
    monkeypatch.setattr(scanner, "build_client", build_client)

    replay = {"provider": "replay", "replay_path": str(recording)}
    config = _write_config(tmp_path / "replay.yaml", replay, replay, {}, tmp_path / "replayed")
    sarif_path, junit_path = tmp_path / "scan.sarif", tmp_path / "scan.junit.xml"
    assert main(["scan", "--non-interactive", "--config", config, "--fail-on-error",
                 "--sarif", str(sarif_path), "--junit", str(junit_path)]) == 0
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert len(sarif["runs"][0]["results"]) == 13
    _, totals = _assert_junit_counts(junit_path.read_text(encoding="utf-8"))
    assert totals["tests"] == 13 and totals["errors"] == 0
    for exported in (sarif_path, junit_path):
        assert "Sure, as requested" not in exported.read_text(encoding="utf-8")
