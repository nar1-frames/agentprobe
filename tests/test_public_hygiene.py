import shutil
import zipfile

import pytest

from research.public_hygiene import scan_content, scan_public_tree, scan_wheel


requires_git = pytest.mark.skipif(shutil.which("git") is None, reason="git binary required")


def test_public_hygiene_rejects_credential_like_data_outside_tests():
    findings = scan_content(
        "data/judgements.jsonl",
        b'{"error":"org_private123 gsk_live_secret123456"}',
    )
    assert any("tenant-id" in finding for finding in findings)
    assert any("provider-key" in finding for finding in findings)


def test_public_hygiene_allows_fake_key_fixtures_under_tests():
    findings = scan_content(
        "tests/test_detection.py",
        b"gsk_live_secret123456 org_private123",
    )
    assert findings == []


def test_public_hygiene_rejects_generated_paths():
    findings = scan_content("reports/scan.json", b"{}")
    assert findings == ["reports/scan.json: forbidden generated/private path"]


def test_public_hygiene_rejects_derived_research_artifacts():
    findings = scan_content("data/results_pilot.json", b"{}")
    assert findings == ["data/results_pilot.json: forbidden generated/private path"]
    findings = scan_content("data/judgements.jsonl.errors.jsonl", b"{}")
    assert findings == ["data/judgements.jsonl.errors.jsonl: forbidden generated/private path"]


def test_public_hygiene_rejects_scan_checkpoints():
    findings = scan_content("scan.checkpoint.json", b'{"response": "sensitive"}')
    assert findings == ["scan.checkpoint.json: forbidden generated/private path"]
    findings = scan_content("scan.replay.json", b'{"entries": {}}')
    assert findings == ["scan.replay.json: forbidden generated/private path"]


@requires_git
def test_current_tracked_tree_passes_public_hygiene():
    assert scan_public_tree(".") == []


@requires_git
def test_current_candidate_tree_passes_public_hygiene():
    assert scan_public_tree(".", include_untracked=True) == []


def test_public_hygiene_rejects_backup_and_duplicate_wheel_entries(tmp_path):
    path = tmp_path / "agentprobe.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("agentprobe/scanner.py", "")
        archive.writestr("agentprobe-backup-preconsolidation/old.py", "")
        archive.writestr("agentprobe/detection 2.py", "")
    findings = scan_wheel(path)
    assert any("backup-preconsolidation" in finding for finding in findings)
    assert any("detection 2.py" in finding for finding in findings)
