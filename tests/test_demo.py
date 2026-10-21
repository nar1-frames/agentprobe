import json
import shutil
import socket
from pathlib import Path

import pytest

from agentprobe import cli
from agentprobe.replay import load_recording
from research.public_hygiene import scan_content


ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "demo"


@pytest.fixture
def demo_cwd(tmp_path, monkeypatch):
    """Run from a copy of demo/ so reports land in a temp reports/ folder."""

    shutil.copytree(DEMO, tmp_path / "demo")
    monkeypatch.chdir(tmp_path)
    for name in ("GROQ_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(name, raising=False)

    def no_network(*_args, **_kwargs):
        raise AssertionError("the offline demo must not open a network connection")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    return tmp_path


def test_demo_scan_runs_offline_through_the_cli(demo_cwd, capsys):
    exit_code = cli.main(["scan", "--non-interactive", "--config", "demo/replay.yaml"])
    assert exit_code == 0, capsys.readouterr().out

    reports = demo_cwd / "reports"
    html = list(reports.glob("*.html"))
    json_reports = list(reports.glob("*.json"))
    assert len(html) == 1 and len(json_reports) == 1
    assert "Mitigation Map" in html[0].read_text(encoding="utf-8")

    report = json.loads(json_reports[0].read_text(encoding="utf-8"))
    assert report["run"]["target_provider"] == "replay"
    assert report["run"]["judge_provider"] == "replay"
    summary = report["summary"]
    assert 10 <= summary["total_attacks"] <= 15
    assert summary["operational_errors"] == 0
    assert summary["verdicts"]["SAFE"] >= 1
    assert summary["verdicts"]["VULNERABLE"] >= 1
    assert len({row["category"] for row in report["results"]}) >= 3


def test_demo_recording_is_valid_and_sanitized():
    path = DEMO / "scan.replay.json"
    assert load_recording(str(path))
    text = path.read_text(encoding="utf-8")
    for needle in ("sk-", "gsk_", "C:\\", "/Users/", "@", "http://", "https://"):
        assert needle not in text, needle
    assert scan_content("demo/scan.replay.json", text.encode("utf-8")) == []


def test_committed_sample_report_shows_mixed_verdicts():
    report = json.loads((ROOT / "docs/demo/demo_report.json").read_text(encoding="utf-8"))
    assert report["summary"]["verdicts"]["SAFE"] >= 1
    assert report["summary"]["verdicts"]["VULNERABLE"] >= 1
    html = (ROOT / "docs/demo/demo_report.html").read_text(encoding="utf-8")
    assert "Mitigation Map" in html


def test_hygiene_allowlist_covers_only_the_demo_recording():
    assert scan_content("demo/other.replay.json", b"{}") != []
    assert scan_content("scan.replay.json", b"{}") != []
