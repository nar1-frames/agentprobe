"""public-scan-01 stays reproducible offline from its committed recording."""

import json
import socket
from pathlib import Path

import pytest

from agentprobe import cli
from agentprobe.replay import load_recording
from research.public_hygiene import scan_content


ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "examples" / "langchain-quickstart-agent"
RECORDING = "examples/langchain-quickstart-agent/scan.replay.json"


@pytest.fixture
def offline(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for name in ("GROQ_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(name, raising=False)

    def no_network(*_args, **_kwargs):
        raise AssertionError("the replayed public scan must not open a network connection")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    return tmp_path


def test_recording_is_valid_and_sanitized():
    path = ROOT / RECORDING
    entries = load_recording(str(path))
    assert len(entries) == 98  # 49 agent responses and 49 judge replies
    text = path.read_text(encoding="utf-8")
    for needle in ("sk-", "gsk_", "C:\\", "/Users/", "@", "http://", "https://", "127.0.0.1"):
        assert needle not in text, needle
    assert scan_content(RECORDING, text.encode("utf-8")) == []


def test_hygiene_allowlist_names_only_the_reviewed_recording():
    assert scan_content("examples/langchain-quickstart-agent/other.replay.json", b"{}") != []
    assert scan_content("examples/scan.replay.json", b"{}") != []


def test_replay_reproduces_the_published_results(offline, capsys):
    config = str(EXAMPLE / "replay.yaml")
    assert cli.main(["scan", "--non-interactive", "--no-color", "--config", config]) == 0
    capsys.readouterr()
    report = json.loads(next((offline / "reports").glob("*.json")).read_text(encoding="utf-8"))
    rows = report["results"]
    complete = [row for row in rows if row["status"] == "complete"]
    assert len(rows) == 49 and len(complete) == 47
    verdicts = {v: sum(row["verdict"] == v for row in complete)
                for v in ("VULNERABLE", "PARTIAL", "SAFE", "SUSPICIOUS")}
    assert verdicts == {"VULNERABLE": 7, "PARTIAL": 1, "SAFE": 39, "SUSPICIOUS": 0}
    assert sorted(row["attack_id"] for row in rows if row["status"] == "error") == [
        "context_manipulation:3", "tool_misuse:3",
    ]
    # The summary agrees with the rows: the two judge errors are not verdicts.
    assert report["summary"]["verdicts"] == verdicts
    assert report["summary"]["operational_errors"] == 2
    assert report["summary"]["findings_by_severity"] == {
        "CRITICAL": 1, "HIGH": 5, "MEDIUM": 2, "LOW": 0,
    }
