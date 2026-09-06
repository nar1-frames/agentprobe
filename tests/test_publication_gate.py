import pytest

from research.publication_gate import check_readiness
from research.protocol import expected_second_label_ids


def _corpus():
    return [{"response_id": "a"}, {"response_id": "b"}]


def _labels():
    return [
        {"response_id": "a", "labeler": "ren", "label": "REFUSED"},
        {"response_id": "b", "labeler": "ren", "label": "REFUSED"},
        {"response_id": "a", "labeler": "friend", "label": "REFUSED"},
    ]


def _judgements(k=5):
    return [
        {"response_id": rid, "judge_model": "judge-70b", "temperature": 0,
         "run_idx": run, "verdict": "SAFE"}
        for rid in ("a", "b") for run in range(k)
    ]


def test_publication_gate_accepts_complete_fixed_k_study():
    report = check_readiness(_corpus(), _judgements(), _labels(), "ren", "friend", 5)
    assert report["ready"] is True


def test_publication_gate_rejects_missing_labels_and_failed_runs():
    rows = _judgements(3)
    rows.append({"response_id": "a", "judge_model": "judge-70b", "temperature": 0,
                 "run_idx": 3, "verdict": "SUSPICIOUS", "error": "429"})
    report = check_readiness(_corpus(), rows, _labels()[:1], "ren", "friend", 5)
    assert report["ready"] is False
    assert any("primary labels cover" in reason for reason in report["blocking_reasons"])
    assert any("operational judge errors" in reason for reason in report["blocking_reasons"])


def test_publication_gate_rejects_an_entirely_missing_expected_condition():
    report = check_readiness(
        _corpus(), _judgements(), _labels(), "ren", "friend", 5,
        expected_configs=["judge-70b@0", "judge-70b@0.7"],
    )
    assert report["ready"] is False
    assert any("missing judge configuration judge-70b@0.7" in reason
               for reason in report["blocking_reasons"])


def test_publication_gate_rejects_duplicate_evidence_rows():
    labels = _labels() + [{"response_id": "a", "labeler": "ren", "label": "COMPLIED"}]
    judgements = _judgements() + [_judgements()[0]]
    report = check_readiness(_corpus(), judgements, labels, "ren", "friend", 5)
    assert report["ready"] is False
    assert any("duplicate" in reason for reason in report["blocking_reasons"])


def test_publication_gate_rejects_failed_target_responses():
    corpus = _corpus()
    corpus[0]["error"] = "provider timeout"
    report = check_readiness(corpus, _judgements(), _labels(), "ren", "friend", 5)
    assert report["ready"] is False
    assert report["target_errors"] == 1
    assert any("target API errors" in reason for reason in report["blocking_reasons"])


def test_publication_gate_rejects_malformed_evidence_rows():
    report = check_readiness(
        _corpus(), _judgements() + [{"response_id": "a"}], _labels(),
        "ren", "friend", 5,
    )
    assert report["ready"] is False
    assert any("missing judge_model" in reason for reason in report["blocking_reasons"])


def test_publication_gate_rejects_nonfinite_expected_temperature():
    with pytest.raises(ValueError, match="finite"):
        check_readiness(
            _corpus(), _judgements(), _labels(), "ren", "friend", 5,
            expected_configs=["judge-70b@nan"],
        )


def test_publication_gate_rejects_fractional_run_index():
    rows = _judgements()
    rows[0]["run_idx"] = 0.5
    report = check_readiness(_corpus(), rows, _labels(), "ren", "friend", 5)
    assert report["ready"] is False
    assert any("invalid run_idx" in reason for reason in report["blocking_reasons"])


def test_publication_gate_fails_closed_on_unhashable_malformed_rows():
    rows = _judgements()
    rows.append({
        "response_id": [], "judge_model": [], "temperature": 0,
        "run_idx": 0, "verdict": "SAFE",
    })
    report = check_readiness(
        _corpus(), rows, _labels() + [None], "ren", "friend", 5,
    )
    assert report["ready"] is False
    assert any("judge row" in reason and "empty response_id" in reason
               for reason in report["blocking_reasons"])
    assert any("label row 4 is not an object" in reason
               for reason in report["blocking_reasons"])


def test_publication_gate_enforces_manifest_second_label_subset():
    corpus = [{"response_id": str(index)} for index in range(10)]
    primary = [
        {"response_id": row["response_id"], "labeler": "ren", "label": "REFUSED"}
        for row in corpus
    ]
    expected_ids = expected_second_label_ids(corpus, 0.3, 42)
    second = [
        {"response_id": response_id, "labeler": "friend", "label": "REFUSED"}
        for response_id in expected_ids
    ]
    judgements = [
        {"response_id": row["response_id"], "judge_model": "judge-70b",
         "temperature": 0, "run_idx": 0, "verdict": "SAFE"}
        for row in corpus
    ]
    ready = check_readiness(
        corpus, judgements, primary + second, "ren", "friend", 1,
        expected_configs=["judge-70b@0"],
        expected_second_overlap_fraction=0.3,
        expected_second_subset_seed=42,
    )
    assert ready["ready"] is True

    second[0]["response_id"] = "not-assigned"
    not_ready = check_readiness(
        corpus, judgements, primary + second, "ren", "friend", 1,
        expected_configs=["judge-70b@0"],
        expected_second_overlap_fraction=0.3,
        expected_second_subset_seed=42,
    )
    assert not_ready["ready"] is False
    assert any("subset does not match" in reason
               for reason in not_ready["blocking_reasons"])


def test_publication_gate_rejects_unexpected_judge_condition():
    extra = [
        {"response_id": rid, "judge_model": "unregistered-judge",
         "temperature": 0, "run_idx": run, "verdict": "SAFE"}
        for rid in ("a", "b") for run in range(5)
    ]
    report = check_readiness(
        _corpus(), _judgements() + extra, _labels(), "ren", "friend", 5,
        expected_configs=["judge-70b@0"],
    )
    assert report["ready"] is False
    assert any("unexpected judge configurations" in reason
               for reason in report["blocking_reasons"])


def test_publication_gate_requires_frozen_target_generation_settings():
    report = check_readiness(
        _corpus(), _judgements(), _labels(), "ren", "friend", 5,
        expected_target_temperature=0.0,
        expected_target_max_tokens=512,
    )
    assert report["ready"] is False
    assert any("target_temperature metadata" in reason
               for reason in report["blocking_reasons"])
