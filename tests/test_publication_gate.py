import pytest

from research._common import canonical_digest, response_id
from research.publication_gate import check_readiness, _jsonable
from research.protocol import attack_library_digest, expected_second_label_ids
from attacks.library import ATTACK_LIBRARY


def _corpus():
    return [{"response_id": "a"}, {"response_id": "b"}]


def _labels(corpus=None):
    corpus = corpus or _corpus()
    digest = canonical_digest(corpus)
    return [
        {"response_id": "a", "labeler": "ren", "label": "REFUSED", "corpus_sha256": digest},
        {"response_id": "b", "labeler": "ren", "label": "REFUSED", "corpus_sha256": digest},
        {"response_id": "a", "labeler": "friend", "label": "REFUSED", "corpus_sha256": digest},
    ]


def _judgements(k=5, corpus=None):
    corpus = corpus or _corpus()
    digest = canonical_digest(corpus)
    return [
        {"response_id": rid, "judge_model": "judge-70b", "temperature": 0,
         "run_idx": run, "verdict": "SAFE", "corpus_sha256": digest}
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
    digest = canonical_digest(corpus)
    for row in primary:
        row["corpus_sha256"] = digest
    expected_ids = expected_second_label_ids(corpus, 0.3, 42)
    second = [
        {"response_id": response_id, "labeler": "friend", "label": "REFUSED",
         "corpus_sha256": digest}
        for response_id in expected_ids
    ]
    judgements = [
        {"response_id": row["response_id"], "judge_model": "judge-70b",
         "temperature": 0, "run_idx": 0, "verdict": "SAFE",
         "corpus_sha256": digest}
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


def test_publication_gate_requires_manifest_provider_provenance():
    report = check_readiness(
        _corpus(), _judgements(), _labels(), "ren", "friend", 5,
        expected_target_provider="groq",
        expected_judge_provider="groq",
        expected_judge_max_tokens=120,
        expected_protocol_manifest_sha256="a" * 64,
    )
    assert report["ready"] is False
    assert any("target provider metadata" in reason for reason in report["blocking_reasons"])
    assert any("judge provider metadata" in reason for reason in report["blocking_reasons"])
    assert any("protocol manifest metadata" in reason for reason in report["blocking_reasons"])


def test_publication_gate_requires_labeling_guide_provenance():
    report = check_readiness(
        _corpus(), _judgements(), _labels(), "ren", "friend", 5,
        expected_labeling_guide_sha256="a" * 64,
    )
    assert report["ready"] is False
    assert any("labeling guide" in reason for reason in report["blocking_reasons"])


def test_publication_gate_requires_exact_provider_configuration_digests():
    corpus = [dict(row, target_config_sha256="b" * 64) for row in _corpus()]
    judgements = [dict(row, judge_config_sha256="b" * 64) for row in _judgements()]
    report = check_readiness(
        corpus, judgements, _labels(), "ren", "friend", 5,
        expected_protocol_manifest_sha256="a" * 64,
        expected_target_config_sha256={"a" * 64},
        expected_judge_config_sha256={("judge-70b", 0.0): "a" * 64},
    )
    assert report["ready"] is False
    assert any("target provider configuration provenance does not match" in reason
               for reason in report["blocking_reasons"])
    assert any("judge provider configuration provenance does not match" in reason
               for reason in report["blocking_reasons"])


def test_publication_gate_requires_explicit_reasoning_and_system_context_metadata():
    report = check_readiness(
        _corpus(), _judgements(), _labels(), "ren", "friend", 5,
        expected_target_reasoning_effort="low",
        expected_target_system_prompt="No tools.",
        expected_judge_reasoning_effort="low",
    )
    assert report["ready"] is False
    assert any("target_reasoning_effort" in reason for reason in report["blocking_reasons"])
    assert any("target_system_prompt" in reason for reason in report["blocking_reasons"])
    assert any("judge reasoning_effort" in reason for reason in report["blocking_reasons"])


def test_publication_gate_diagnostics_are_json_serializable():
    value = _jsonable({("judge", 0.0): "a" * 64, "digests": {"b" * 64}})
    assert value["judge@0"] == "a" * 64
    assert value["digests"] == ["b" * 64]


def test_publication_gate_rejects_evidence_from_a_different_corpus():
    corpus = _corpus()
    judgements = _judgements()
    labels = _labels()
    judgements[0]["corpus_sha256"] = "0" * 64
    labels[0]["corpus_sha256"] = "0" * 64
    report = check_readiness(corpus, judgements, labels, "ren", "friend", 5)
    assert report["ready"] is False
    assert any("judge evidence is not bound" in reason
               for reason in report["blocking_reasons"])
    assert any("human labels are not bound" in reason
               for reason in report["blocking_reasons"])


def test_manifest_backed_gate_rejects_forged_attack_metadata():
    category = next(iter(ATTACK_LIBRARY))
    attack = ATTACK_LIBRARY[category][0]
    corpus = [{
        "response_id": response_id(category, 0, "target-8b"),
        "category": category,
        "attack_index": 0,
        "severity": attack["severity"],
        "attack_prompt": "forged prompt",
        "target_model": "target-8b",
        "target_temperature": 0.0,
        "max_tokens": 512,
        "response": "refused",
    }]
    digest = canonical_digest(corpus)
    judgements = [{
        "response_id": corpus[0]["response_id"], "judge_model": "judge-70b",
        "temperature": 0.0, "run_idx": 0, "verdict": "SAFE",
        "corpus_sha256": digest,
    }]
    labels = [
        {"response_id": corpus[0]["response_id"], "labeler": labeler,
         "label": "REFUSED", "corpus_sha256": digest}
        for labeler in ("ren", "friend")
    ]
    report = check_readiness(
        corpus, judgements, labels, "ren", "friend", 1,
        expected_configs=["judge-70b@0"],
        expected_target_models=["target-8b"],
        expected_corpus_rows=1,
        expected_attack_library_sha256=attack_library_digest(ATTACK_LIBRARY),
        expected_target_temperature=0.0,
        expected_target_max_tokens=512,
    )
    assert report["ready"] is False
    assert any("attack prompt differs from library" in reason
               for reason in report["blocking_reasons"])
