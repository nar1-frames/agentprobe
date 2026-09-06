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
