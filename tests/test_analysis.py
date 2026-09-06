import math

from research.analyze import (
    choose_reference_config, judge_majority, rq2_reliability,
    rq4_proxy_error_overlap,
)


def test_judge_majority_excludes_errors_and_marks_ties():
    rows = [
        {"response_id": "ok", "judge_model": "judge-70b", "temperature": 0,
         "verdict": "VULNERABLE"},
        {"response_id": "ok", "judge_model": "judge-70b", "temperature": 0,
         "verdict": "SAFE"},
        {"response_id": "ok", "judge_model": "judge-70b", "temperature": 0,
         "verdict": "VULNERABLE"},
        {"response_id": "failed", "judge_model": "judge-70b", "temperature": 0,
         "verdict": "SUSPICIOUS", "error": "429"},
        {"response_id": "tie", "judge_model": "judge-70b", "temperature": 0,
         "verdict": "VULNERABLE"},
        {"response_id": "tie", "judge_model": "judge-70b", "temperature": 0,
         "verdict": "SAFE"},
    ]
    result = judge_majority(rows)
    assert result[("ok", "judge-70b", 0.0)][0] == "COMPLIED"
    assert ("failed", "judge-70b", 0.0) not in result
    assert result[("tie", "judge-70b", 0.0)][0] == "SUSPICIOUS"


def test_reference_prefers_configured_or_largest_model():
    majo = {
        ("r1", "judge-8b", 0.0): ("COMPLIED", []),
        ("r1", "judge-70b", 0.7): ("REFUSED", []),
    }
    assert choose_reference_config(majo) == ("judge-70b", 0.7)
    assert choose_reference_config(majo, preferred_model="judge-8b") == ("judge-8b", 0.0)


def test_reference_temperature_selector_fails_closed_when_missing():
    majo = {("r1", "judge-8b", 0.0): ("COMPLIED", [])}
    try:
        choose_reference_config(
            majo, preferred_model="judge-8b", preferred_temperature=0.7
        )
    except ValueError as exc:
        assert "not found" in str(exc)
    else:
        raise AssertionError("missing reference condition was silently substituted")


def test_reliability_excludes_failed_and_incomplete_runs():
    rows = []
    rows.extend([
        {"response_id": "a", "judge_model": "judge-8b", "temperature": 0,
         "verdict": "SAFE"},
        {"response_id": "a", "judge_model": "judge-8b", "temperature": 0,
         "verdict": "SAFE"},
    ])
    rows.extend([
        {"response_id": "b", "judge_model": "judge-8b", "temperature": 0,
         "verdict": "SAFE"},
    ])
    rows.append({"response_id": "b", "judge_model": "judge-8b", "temperature": 0,
                 "verdict": "SAFE", "error": "429"})
    out = {"rq2": []}
    rq2_reliability(rows, out, expected_response_ids={"a", "b", "c"})
    result = out["rq2"][0]
    assert result["items"] == 1
    assert result["incomplete_items_excluded"] == 2
    assert result["missing_item_groups"] == 1
    assert result["judge_errors_excluded"] == 1
    assert math.isclose(result["fleiss_kappa"], 1.0)
    assert result["fleiss_kappa_ci_95"] == [1.0, 1.0]


def test_proxy_error_overlap_is_explicitly_labeled():
    corpus = [{"response_id": "a", "keyword_verdict": "SAFE"}]
    labels = {"a": {"ren": "COMPLIED"}}
    majority = {
        ("a", "judge-8b", 0.0): ("COMPLIED", ["COMPLIED"]),
    }
    out = {}
    rq4_proxy_error_overlap(corpus, labels, majority, "ren", out)
    result = out["rq4_proxy_error_overlap"]
    assert result["n"] == 1
    assert result["joint_errors"] == 0
    assert "proxy" in result["interpretation"]
    assert len(result["error_overlap_rate_ci_95"]) == 2
