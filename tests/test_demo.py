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


def test_scan_non_interactive_verbose_shows_progress(demo_cwd, capsys):
    exit_code = cli.main([
        "scan", "--non-interactive", "--verbose", "--config", "demo/replay.yaml",
    ])
    out = capsys.readouterr().out
    assert exit_code == 0, out
    assert "[ROLE_CONFUSION] 6 prompts" in out
    assert "[SAFE]" in out or "[VULNERABLE]" in out
    assert "category total:" in out
    last_tally = out.rindex("category total:")
    assert last_tally < out.index("Scan summary:") < out.index("HTML report saved to:")
    assert all(ord(ch) < 128 for ch in out)


def test_scan_non_interactive_quiet_without_verbose(demo_cwd, capsys):
    assert cli.main(["scan", "--non-interactive", "--config", "demo/replay.yaml"]) == 0
    out = capsys.readouterr().out
    assert "category total:" not in out
    assert "prompts" not in out
    assert out.lstrip().startswith("Scan summary:")


def test_demo_command_runs_offline_and_prints_intro(demo_cwd, capsys):
    exit_code = cli.main(["demo"])
    out = capsys.readouterr().out
    assert exit_code == 0, out
    assert out.startswith(
        "AgentProbe offline demo: replays a recorded scan of openai/gpt-oss-20b, "
        "no keys or network needed.\n"
        "Each attack prompt below is judged from the recording; verdict tags are "
        "explained at the end.\n\n"
    )
    assert "category total:" in out
    assert "Scan summary:" in out
    assert "HTML report saved to:" in out and "JSON report saved to:" in out
    assert out.index("Scan summary:") < out.index("HTML report saved to:")
    assert all(ord(ch) < 128 for ch in out)
    assert len(list((demo_cwd / "reports").glob("*.json"))) == 1


def test_demo_command_reports_missing_files_clearly(tmp_path, monkeypatch, capsys):
    missing = tmp_path / "nowhere" / "replay.yaml"
    monkeypatch.setattr(cli, "DEMO_CONFIG", str(missing))
    monkeypatch.chdir(tmp_path)
    assert cli.main(["demo"]) == 2
    out = capsys.readouterr().out
    assert str(missing) in out
    assert "demo files not found" in out
    assert "repository root" in out
    assert "Scan summary:" not in out
