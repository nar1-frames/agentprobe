import pytest

from disclosure import tracker
from disclosure.authorization import (
    AuthorizationError,
    classify_finding,
    load_authorization,
    require_authorization,
)


def test_tracker_enforces_disclosure_lifecycle(tmp_path):
    path = str(tmp_path / "tracker.json")
    finding_id = tracker.add_finding(
        target_id="fixture-target",
        title="fixture finding",
        category="tool_misuse",
        classification="PAYABLE",
        severity="HIGH",
        discovered_date="2026-09-05",
        path=path,
    )
    with pytest.raises(ValueError, match="Invalid disclosure transition"):
        tracker.update_status(finding_id, "RESOLVED", "2026-09-05", path=path)

    tracker.update_status(finding_id, "SUBMITTED", "2026-09-05", path=path)
    tracker.update_status(finding_id, "TRIAGED", "2026-09-05", path=path)
    tracker.update_status(finding_id, "ACCEPTED", "2026-09-05", path=path)
    tracker.update_status(finding_id, "RESOLVED", "2026-09-05", path=path)
    tracker.update_status(finding_id, "DISCLOSED", "2026-09-05", path=path)
    assert tracker.get_finding(finding_id, path=path)["status"] == "DISCLOSED"


def test_terminal_finding_cannot_be_reopened(tmp_path):
    path = str(tmp_path / "tracker.json")
    finding_id = tracker.add_finding(
        "fixture-target", "fixture", "jailbreak", "OUT_OF_SCOPE", "LOW",
        "2026-09-05", path=path,
    )
    tracker.update_status(finding_id, "NOT_APPLICABLE", "2026-09-05", path=path)
    with pytest.raises(ValueError, match="Invalid disclosure transition"):
        tracker.update_status(finding_id, "DRAFT", "2026-09-05", path=path)


def test_tracker_supports_bare_paths_and_atomic_replacement(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    finding_id = tracker.add_finding(
        "fixture-target", "fixture", "tool_misuse", "PAYABLE", "HIGH",
        "2026-09-05", path="tracker.json",
    )
    assert tracker.get_finding(finding_id, path="tracker.json")["status"] == "DRAFT"


def _authorization_yaml(**overrides):
    fields = {
        "target_id": "fixture-target",
        "program_name": "Fixture program",
        "program_url": "https://example.test/program",
        "platform": "fixture",
        "automated_testing_permitted": "false",
        "confirmed": "false",
        "authorized_by": "",
        "authorized_date": "",
    }
    fields.update(overrides)
    def yaml_value(value):
        if isinstance(value, str):
            return repr(value)
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value)

    return f"""
target_id: {fields['target_id']}
program_name: {fields['program_name']}
program_url: {fields['program_url']}
platform: {fields['platform']}
rules:
  automated_testing_permitted: {yaml_value(fields['automated_testing_permitted'])}
  min_reproducibility: 0.5
authorization:
  confirmed: {yaml_value(fields['confirmed'])}
  authorized_by: {fields['authorized_by']!r}
  authorized_date: {fields['authorized_date']!r}
"""


def test_authorization_does_not_treat_string_false_as_true(tmp_path):
    path = tmp_path / "fixture.yaml"
    path.write_text(_authorization_yaml())
    with pytest.raises(AuthorizationError, match="YAML boolean"):
        load_authorization(path)


def test_confirmed_authorization_requires_human_provenance(tmp_path):
    path = tmp_path / "fixture.yaml"
    path.write_text(_authorization_yaml(
        automated_testing_permitted=False,
        confirmed=True,
    ))
    with pytest.raises(AuthorizationError, match="authorized_by"):
        load_authorization(path)


def test_authorization_normalizes_unquoted_yaml_date(tmp_path):
    path = tmp_path / "fixture.yaml"
    contents = _authorization_yaml(
        automated_testing_permitted=False,
        confirmed=True,
        authorized_by="ren",
        authorized_date="2026-09-05",
    ).replace("authorized_date: '2026-09-05'", "authorized_date: 2026-09-05")
    path.write_text(contents)
    auth = load_authorization(path)
    assert auth.authorized_date == "2026-09-05"


def test_authorization_rejects_unknown_mode_before_lookup(tmp_path):
    with pytest.raises(AuthorizationError, match="Unknown testing mode"):
        require_authorization("fixture-target", mode="unknown", auth_dir=tmp_path)


def test_classification_rejects_invalid_reproducibility():
    auth = type("Auth", (), {"min_reproducibility": 0.5})()
    with pytest.raises(ValueError, match="between 0 and 1"):
        classify_finding("tool_misuse", True, float("nan"), auth)
