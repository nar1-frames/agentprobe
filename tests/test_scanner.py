import json
from types import SimpleNamespace

from agentprobe import scanner


class _TargetClient:
    def __init__(self):
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    @staticmethod
    def create(**_kwargs):
        return SimpleNamespace(
            choices=[SimpleNamespace(
                message=SimpleNamespace(
                    content="I can't help with that, and I won't provide it."
                )
            )]
        )


def _config(report_dir):
    return {
        "target": {
            "provider": "ollama", "model": "target-3b", "max_tokens": 32,
            "temperature": 0.0, "timeout_seconds": 1,
        },
        "judge": {
            "provider": "ollama", "model": "judge-8b", "max_tokens": 16,
            "temperature": 0.1, "timeout_seconds": 1,
        },
        "scan": {
            "categories": ["jailbreak"], "rate_limit_seconds": 0,
            "retries": 0, "retry_delay_seconds": 0,
        },
        "output": {"report_format": "json", "report_dir": str(report_dir)},
    }


def test_package_scan_routes_target_and_emits_a_complete_report(tmp_path, monkeypatch):
    config = _config(tmp_path / "reports")
    monkeypatch.setattr(scanner, "load_config", lambda _path: config)
    monkeypatch.setattr(scanner, "build_client", lambda _block: _TargetClient())

    run = scanner.run_configured_scan("fixture.yaml")

    assert run["html_path"] is None
    report = json.loads((tmp_path / "reports").glob("scan_*.json").__next__().read_text())
    assert report["summary"]["total_attacks"] == 8
    assert report["summary"]["operational_errors"] == 0
    assert all(row["method"] == "keyword" for row in report["results"])


def test_package_scan_checkpoint_can_resume(tmp_path, monkeypatch):
    library = {
        "fixture": [{
            "prompt": "fixture attack", "severity": "LOW",
            "description": "fixture", "_library_index": 1,
        }]
    }
    calls = []

    class Target:
        def __init__(self):
            self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

        @staticmethod
        def create(**kwargs):
            calls.append(kwargs["messages"][0]["content"])
            return SimpleNamespace(
                choices=[SimpleNamespace(
                    message=SimpleNamespace(
                        content="I can't help with that, and I won't provide it."
                    )
                )]
            )

    checkpoint = tmp_path / "scan.checkpoint.json"
    first = scanner.run_full_scan(
        Target(), "target-3b", object(), "judge-8b", library, 0,
        checkpoint_path=str(checkpoint), run_metadata={"config_sha256": "a" * 64},
    )
    second = scanner.run_full_scan(
        Target(), "target-3b", object(), "judge-8b", library, 0,
        checkpoint_path=str(checkpoint), resume=True,
        run_metadata={"config_sha256": "a" * 64},
    )

    assert len(first["fixture"]) == len(second["fixture"]) == 1
    assert calls == ["fixture attack"]
