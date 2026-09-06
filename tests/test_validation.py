from research._common import response_id
from research.validate import validate_dataset
from attacks.library import ATTACK_LIBRARY


def _corpus_row(index=0):
    return {
        "response_id": response_id("jailbreak", index, "target-8b"),
        "category": "jailbreak",
        "attack_index": index,
        "target_model": "target-8b",
        "response": "fixture response",
    }


def test_validation_accepts_operational_errors_but_reports_them():
    corpus = [_corpus_row()]
    judgements = [{
        "response_id": corpus[0]["response_id"], "judge_model": "judge-70b",
        "temperature": 0, "run_idx": 0, "verdict": "SUSPICIOUS", "error": "429",
    }]
    report = validate_dataset(corpus, judgements)
    assert report["valid"] is True
    assert report["operational_judge_errors"] == 1
    assert report["valid_judgements"] == 0


def test_validation_rejects_duplicate_and_orphan_keys():
    corpus = [_corpus_row(), _corpus_row()]
    labels = [{"response_id": "not-in-corpus", "labeler": "ren", "label": "COMPLIED"}]
    report = validate_dataset(corpus, labels=labels)
    assert report["valid"] is False
    assert any("duplicate response_id" in error for error in report["errors"])
    assert any("orphan response_id" in error for error in report["errors"])


def test_validation_rejects_corpus_prompt_or_severity_drift():
    corpus = [_corpus_row()]
    corpus[0].update({"attack_prompt": "tampered", "severity": "LOW"})
    report = validate_dataset(corpus, attack_library=ATTACK_LIBRARY)
    assert report["valid"] is False
    assert any("attack prompt differs" in error for error in report["errors"])
    assert any("severity differs" in error for error in report["errors"])


def test_validation_rejects_fractional_run_index_and_nonfinite_temperature():
    corpus = [_corpus_row()]
    judgements = [
        {
            "response_id": corpus[0]["response_id"], "judge_model": "judge-70b",
            "temperature": "nan", "run_idx": 0, "verdict": "SAFE",
        },
        {
            "response_id": corpus[0]["response_id"], "judge_model": "judge-70b",
            "temperature": 0, "run_idx": 0.5, "verdict": "SAFE",
        },
    ]
    report = validate_dataset(corpus, judgements)
    assert report["valid"] is False
    assert any("temperature is not finite" in error for error in report["errors"])
    assert any("temperature/run_idx is not numeric" in error for error in report["errors"])


def test_validation_fails_closed_on_non_object_rows_without_crashing():
    report = validate_dataset([[]], judgements=["not-an-object"], labels=[None])
    assert report["valid"] is False
    assert any("corpus row 1: expected a JSON object" in error for error in report["errors"])
    assert any("judgement row 1: expected a JSON object" in error for error in report["errors"])
    assert any("label row 1: expected a mapping" in error for error in report["errors"])


def test_validation_reports_legacy_corpus_without_target_temperature_metadata():
    report = validate_dataset([_corpus_row()])
    assert report["valid"] is True
    assert any("lack target_temperature metadata" in warning
               for warning in report["warnings"])


def test_validation_rejects_unhashable_labeler_and_invalid_generation_settings():
    corpus = [_corpus_row()]
    corpus[0]["target_temperature"] = 2.5
    labels = [{"response_id": corpus[0]["response_id"], "labeler": [], "label": "SAFE"}]
    report = validate_dataset(corpus, labels=labels)
    assert report["valid"] is False
    assert any("target_temperature" in error for error in report["errors"])
    assert any("labeler is empty" in error for error in report["errors"])
