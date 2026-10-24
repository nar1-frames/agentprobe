"""The composite action's gate: SARIF in, pass/fail and step outputs out."""

import importlib.util
import json
import socket
from pathlib import Path

import pytest
import yaml

import agentprobe
from agentprobe import cli


ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("action_gate", ROOT / "action" / "gate.py")
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)


@pytest.fixture
def offline(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for name in ("GROQ_API_KEY", "OPENAI_API_KEY", "GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY"):
        monkeypatch.delenv(name, raising=False)

    def no_network(*_args, **_kwargs):
        raise AssertionError("the gate tests must not open a network connection")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    return tmp_path


@pytest.fixture
def demo_sarif(offline, capsys):
    path = offline / "demo.sarif"
    assert cli.main(["demo", "--no-color", "--sarif", str(path)]) == 0
    capsys.readouterr()
    return path


def _harness_sarif(directory, mode, capsys):
    path = directory / f"harness-{mode}.sarif"
    assert cli.main(["harness", "--mode", mode, "--no-color", "--sarif", str(path)]) == 0
    capsys.readouterr()
    return path


def _outputs(path):
    return dict(line.split("=", 1) for line in path.read_text(encoding="utf-8").splitlines())


def test_demo_counts_match_the_recorded_scan(demo_sarif):
    counts = gate.count_scan(gate.load_results(str(demo_sarif)))
    assert counts == {"SAFE": 10, "SUSPICIOUS": 0, "PARTIAL": 1, "VULNERABLE": 3,
                      "operational_errors": 0}


@pytest.mark.parametrize("fail_on, expected", [
    ("vulnerable", 1), ("partial", 1), ("suspicious", 1), ("never", 0), ("VULNERABLE", 1),
])
def test_scan_threshold(demo_sarif, capsys, fail_on, expected):
    code = gate.main(["--sarif", str(demo_sarif), "--command", "demo", "--fail-on", fail_on])
    assert code == expected
    out = capsys.readouterr().out
    assert out.startswith("AgentProbe: FAIL" if expected else "AgentProbe: PASS")


def test_threshold_reasons_name_only_verdicts_at_or_above():
    counts = {"SAFE": 5, "SUSPICIOUS": 2, "PARTIAL": 1, "VULNERABLE": 0, "operational_errors": 0}
    assert gate.decide("scan", counts, "vulnerable", True) == (False, [])
    failed, reasons = gate.decide("scan", counts, "suspicious", True)
    assert failed and reasons == ["1 PARTIAL, 2 SUSPICIOUS at or above fail-on: suspicious"]


def test_operational_errors_fail_only_when_asked():
    counts = {"SAFE": 1, "SUSPICIOUS": 0, "PARTIAL": 0, "VULNERABLE": 0, "operational_errors": 2}
    assert gate.decide("scan", counts, "never", False) == (False, [])
    failed, reasons = gate.decide("scan", counts, "never", True)
    assert failed and "2 operational error(s)" in reasons[0]


def test_scan_error_rows_are_errors_not_verdicts():
    results = [
        {"kind": "open", "properties": {"verdict": "SUSPICIOUS", "status": "error"}},
        {"kind": "fail", "properties": {"verdict": "VULNERABLE", "status": "complete"}},
    ]
    counts = gate.count_scan(results)
    assert counts["operational_errors"] == 1 and counts["SUSPICIOUS"] == 0
    assert counts["VULNERABLE"] == 1


def test_guarded_harness_passes_and_vulnerable_harness_fails(offline, capsys):
    guarded = _harness_sarif(offline, "guarded", capsys)
    vulnerable = _harness_sarif(offline, "vulnerable", capsys)
    assert gate.main(["--sarif", str(guarded), "--command", "harness"]) == 0
    assert gate.main(["--sarif", str(vulnerable), "--command", "harness"]) == 1
    assert "reached their objective" in capsys.readouterr().out
    assert gate.main(["--sarif", str(vulnerable), "--command", "harness",
                      "--fail-on", "never"]) == 0


def test_harness_operational_errors_are_parsed_from_the_message():
    results = [{"kind": "open", "message": {"text": "operational errors: 3"}},
               {"kind": "fail", "message": {"text": "control failed"}}]
    assert gate.count_harness(results) == {
        "attacks_succeeded": 0, "controls_failed": 1, "operational_errors": 3,
    }


def test_writes_step_outputs_and_summary(demo_sarif, tmp_path, monkeypatch, capsys):
    outputs, summary = tmp_path / "out.txt", tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_OUTPUT", str(outputs))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    assert gate.main(["--sarif", str(demo_sarif), "--command", "demo", "--fail-on", "never"]) == 0
    assert _outputs(outputs) == {
        "safe": "10", "suspicious": "0", "partial": "1", "vulnerable": "3",
        "operational-errors": "0", "result": "pass",
    }
    assert "### AgentProbe demo: PASS" in summary.read_text(encoding="utf-8")


def test_nonzero_agentprobe_exit_fails_without_reading_sarif(offline, monkeypatch, capsys):
    outputs = offline / "out.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(outputs))
    code = gate.main(["--sarif", "missing.sarif", "--command", "scan", "--exit-code", "2"])
    assert code == 1
    assert "agentprobe exited 2" in capsys.readouterr().out
    assert _outputs(outputs) == {"result": "fail"}


def test_missing_or_malformed_sarif_fails(offline, capsys):
    assert gate.main(["--sarif", "missing.sarif", "--command", "scan"]) == 1
    bad = offline / "bad.sarif"
    bad.write_text(json.dumps({"runs": []}), encoding="utf-8")
    assert gate.main(["--sarif", str(bad), "--command", "scan"]) == 1
    assert "cannot read SARIF" in capsys.readouterr().out


def test_rejects_unknown_command_or_threshold(offline, capsys):
    assert gate.main(["--sarif", "x", "--command", "deploy"]) == 2
    assert gate.main(["--sarif", "x", "--command", "scan", "--fail-on", "high"]) == 2


def test_action_installs_the_matching_release_by_default():
    action = yaml.safe_load((ROOT / "action" / "action.yml").read_text(encoding="utf-8"))
    assert action["inputs"]["package"]["default"] == f"agentprobe-security=={agentprobe.__version__}"
    assert action["runs"]["using"] == "composite"
