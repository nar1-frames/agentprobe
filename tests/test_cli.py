import json

import agentprobe_v11

from agentprobe.cli import main


def _run_with_row(method):
    attack = {"prompt": "fixture", "severity": "LOW", "description": "fixture"}
    return {
        "results": {"fixture": [(attack, "response", "SAFE", None, "ok", method)]},
        "html_path": None,
        "json_path": None,
    }


def test_noninteractive_scan_can_fail_on_operational_errors(monkeypatch, capsys):
    monkeypatch.setattr(agentprobe_v11, "run_configured_scan",
                        lambda _config: _run_with_row("judge-error"))
    assert main(["scan", "--non-interactive", "--fail-on-error"]) == 3
    assert "1 operational error(s) recorded" in capsys.readouterr().out


def test_noninteractive_scan_succeeds_when_no_operational_errors(monkeypatch):
    monkeypatch.setattr(agentprobe_v11, "run_configured_scan",
                        lambda _config: _run_with_row("keyword"))
    assert main(["scan", "--non-interactive", "--fail-on-error"]) == 0


def test_noninteractive_scan_passes_checkpoint_options(monkeypatch):
    received = {}

    def fake_run(config, **kwargs):
        received["config"] = config
        received.update(kwargs)
        return _run_with_row("keyword")

    monkeypatch.setattr(agentprobe_v11, "run_configured_scan", fake_run)
    assert main([
        "scan", "--non-interactive", "--checkpoint", "reports/run.checkpoint.json",
        "--resume",
    ]) == 0
    assert received == {
        "config": "config.yaml",
        "checkpoint_path": "reports/run.checkpoint.json",
        "resume": True,
    }


def test_harness_json_output_is_versioned(tmp_path):
    path = tmp_path / "harness.json"
    assert main(["harness", "--mode", "guarded", "--json", str(path)]) == 0
    report = json.loads(path.read_text(encoding="utf-8"))
    assert report["artifact_type"] == "agentprobe_harness"
    assert report["summary"]["controls_passed"] == 1
