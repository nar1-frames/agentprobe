from research.public_hygiene import scan_content, scan_public_tree


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


def test_current_tracked_tree_passes_public_hygiene():
    assert scan_public_tree(".") == []


def test_current_candidate_tree_passes_public_hygiene():
    assert scan_public_tree(".", include_untracked=True) == []
