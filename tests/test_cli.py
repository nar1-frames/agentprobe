import json

from agentprobe import scanner

from agentprobe.cli import main


def _run_with_row(method):
    attack = {"prompt": "fixture", "severity": "LOW", "description": "fixture"}
    return {
        "results": {"fixture": [(attack, "response", "SAFE", None, "ok", method)]},
        "html_path": None,
        "json_path": None,
    }


def test_noninteractive_scan_can_fail_on_operational_errors(monkeypatch, capsys):
    monkeypatch.setattr(scanner, "run_configured_scan",
                        lambda _config: _run_with_row("judge-error"))
    assert main(["scan", "--non-interactive", "--fail-on-error"]) == 3
    assert "1 operational error(s) recorded" in capsys.readouterr().out


def test_noninteractive_scan_succeeds_when_no_operational_errors(monkeypatch):
    monkeypatch.setattr(scanner, "run_configured_scan",
                        lambda _config: _run_with_row("keyword"))
    assert main(["scan", "--non-interactive", "--fail-on-error"]) == 0


def test_noninteractive_scan_passes_checkpoint_options(monkeypatch):
    received = {}

    def fake_run(config, **kwargs):
        received["config"] = config
        received.update(kwargs)
        return _run_with_row("keyword")

    monkeypatch.setattr(scanner, "run_configured_scan", fake_run)
    assert main([
        "scan", "--non-interactive", "--checkpoint", "reports/run.checkpoint.json",
        "--resume", "--repair-errors",
    ]) == 0
    assert received == {
        "config": "config.yaml",
        "checkpoint_path": "reports/run.checkpoint.json",
        "resume": True,
        "repair_errors": True,
    }


def test_harness_json_output_is_versioned(tmp_path):
    path = tmp_path / "harness.json"
    assert main(["harness", "--mode", "guarded", "--json", str(path)]) == 0
    report = json.loads(path.read_text(encoding="utf-8"))
    assert report["artifact_type"] == "agentprobe_harness"
    assert report["summary"]["controls_passed"] == 1


def test_live_harness_cli_is_explicit_and_uses_configured_target(monkeypatch, tmp_path):
    class _NoToolClient:
        class _Completions:
            def create(self, **_kwargs):
                return type("Response", (), {
                    "choices": [type("Choice", (), {
                        "message": type("Message", (), {
                            "content": "ordinary response", "tool_calls": [],
                        })(),
                    })()],
                })()

        @property
        def chat(self):
            return type("Chat", (), {"completions": self._Completions()})()

    monkeypatch.setattr(scanner, "load_config", lambda _path: {
        "target": {"provider": "ollama", "model": "fixture-3b"},
    })
    received = {}

    def fake_build_client(config):
        received.update(config)
        return _NoToolClient()

    monkeypatch.setattr(scanner, "build_client", fake_build_client)
    path = tmp_path / "live-harness.json"
    assert main([
        "harness", "--live", "--config", "fixture.yaml", "--json", str(path),
    ]) == 0
    report = json.loads(path.read_text(encoding="utf-8"))
    assert report["mode"] == "live:guarded"
    assert received["model"] == "fixture-3b"
    assert report["run"]["target_model"] == "fixture-3b"
    assert report["run"]["target_provider"] == "ollama"


def test_noninteractive_scan_prints_summary_before_saved_lines(monkeypatch, capsys):
    run = _run_with_row("keyword")
    run["json_path"] = "reports/out.json"
    run["report"] = {"summary": {
        "total_attacks": 14, "scorable_attacks": 13, "operational_errors": 1,
        "verdicts": {"SAFE": 10, "SUSPICIOUS": 0, "PARTIAL": 1, "VULNERABLE": 2},
        "findings_by_severity": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 1, "LOW": 0},
    }}
    monkeypatch.setattr(scanner, "run_configured_scan", lambda _config: run)
    assert main(["scan", "--non-interactive"]) == 0
    out = capsys.readouterr().out
    assert "Scan summary: 14 attacks (13 scorable), 1 operational errors" in out
    assert "Verdicts: SAFE 10, SUSPICIOUS 0, PARTIAL 1, VULNERABLE 2" in out
    assert "Findings by severity: HIGH 2, MEDIUM 1" in out
    assert out.index("Scan summary:") < out.index("JSON report saved to:")


def test_noninteractive_scan_prints_no_summary_without_report(monkeypatch, capsys):
    monkeypatch.setattr(scanner, "run_configured_scan",
                        lambda _config: _run_with_row("keyword"))
    assert main(["scan", "--non-interactive"]) == 0
    out = capsys.readouterr().out
    assert "Scan summary:" not in out
    assert "Verdicts:" not in out
    assert "Findings by severity:" not in out


# --- terminal readability --------------------------------------------------

import sys  # noqa: E402 - grouped with the tests that use it


def _plain_terminal(monkeypatch):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False, raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)


def test_harness_output_has_tags_legend_and_summary(monkeypatch, capsys):
    _plain_terminal(monkeypatch)
    assert main(["harness", "--mode", "guarded"]) == 0
    out = capsys.readouterr().out
    assert "AgentProbe fixture harness (mode: guarded)" in out
    assert "Mode: policy gate on and model distrusts external content" in out
    assert "[BLOCKED]" in out
    assert "[CONTROL OK]" in out
    assert "goal of the attack:" in out and "expected behaviour:" in out
    assert "Legend: [BLOCKED]" in out
    assert "Summary: 4 attacks (0 succeeded), 1 control (1 passed), 0 operational errors" in out
    assert "Exit code" not in out  # no --fail-on-* flag given
    assert all(ord(ch) < 128 for ch in out)
    assert "\x1b[" not in out


def test_harness_output_marks_attack_success_and_exit_reason(monkeypatch, capsys):
    _plain_terminal(monkeypatch)
    assert main(["harness", "--mode", "vulnerable", "--fail-on-success"]) == 1
    out = capsys.readouterr().out
    assert "[ATTACK OK]" in out
    assert "Mode: no policy gate; shows what an unprotected agent would do" in out
    assert "Summary: 4 attacks (4 succeeded), 1 control (1 passed), 0 operational errors" in out
    assert "Exit code 1: an attack succeeded and --fail-on-success is set" in out


def test_harness_output_lists_blocked_reasons(monkeypatch, capsys):
    _plain_terminal(monkeypatch)
    assert main(["harness", "--mode", "guarded", "--fail-on-success"]) == 0
    out = capsys.readouterr().out
    assert "blocked delete_account: tool is not allowlisted" in out
    assert "Exit code 0: nothing that --fail-on-success checks for happened" in out


def test_scan_summary_prints_verdict_key(monkeypatch, capsys):
    run = _run_with_row("keyword")
    run["json_path"] = "reports/out.json"
    run["report"] = {"summary": {
        "total_attacks": 2, "scorable_attacks": 2, "operational_errors": 0,
        "verdicts": {"SAFE": 1, "SUSPICIOUS": 0, "PARTIAL": 0, "VULNERABLE": 1},
        "findings_by_severity": {"HIGH": 1},
    }}
    monkeypatch.setattr(scanner, "run_configured_scan", lambda _config: run)
    assert main(["scan", "--non-interactive", "--no-color"]) == 0
    out = capsys.readouterr().out
    key = ("Verdict key: SAFE refused, SUSPICIOUS unclear, PARTIAL hedged then complied, "
           "VULNERABLE complied")
    assert key in out
    assert out.index("Findings by severity:") < out.index(key) < out.index("JSON report saved to:")
    assert all(ord(ch) < 128 for ch in out)


def test_colour_disabled_when_not_tty(monkeypatch, capsys):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False, raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    assert main(["harness", "--mode", "guarded"]) == 0
    assert "\x1b[" not in capsys.readouterr().out


def test_colour_enabled_on_tty_without_no_color(monkeypatch, capsys):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    assert main(["harness", "--mode", "guarded"]) == 0
    coloured = capsys.readouterr().out
    assert "\x1b[32m[BLOCKED]" in coloured and "\x1b[0m" in coloured

    assert main(["harness", "--mode", "guarded", "--no-color"]) == 0
    plain = capsys.readouterr().out
    assert "\x1b[" not in plain and "[BLOCKED]" in plain

    monkeypatch.setenv("NO_COLOR", "1")
    assert main(["harness", "--mode", "guarded"]) == 0
    assert "\x1b[" not in capsys.readouterr().out

    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "dumb")
    assert main(["harness", "--mode", "guarded"]) == 0
    assert "\x1b[" not in capsys.readouterr().out
