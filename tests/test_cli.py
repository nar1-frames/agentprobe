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

    monkeypatch.setattr(agentprobe_v11, "load_config", lambda _path: {
        "target": {"provider": "ollama", "model": "fixture-3b"},
    })
    received = {}

    def fake_build_client(config):
        received.update(config)
        return _NoToolClient()

    monkeypatch.setattr(agentprobe_v11, "build_client", fake_build_client)
    path = tmp_path / "live-harness.json"
    assert main([
        "harness", "--live", "--config", "fixture.yaml", "--json", str(path),
    ]) == 0
    report = json.loads(path.read_text(encoding="utf-8"))
    assert report["mode"] == "live:guarded"
    assert received["model"] == "fixture-3b"
