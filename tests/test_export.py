from research.export import render_markdown


def test_export_renders_analysis_tables_and_intervals():
    text = render_markdown({
        "rq1": [{
            "judge_model": "judge-70b", "temperature": 0.0, "n": 17,
            "accuracy": 0.5, "accuracy_ci_95": [0.2, 0.8],
            "cohens_kappa": 0.1, "cohens_kappa_ci_95": [-0.2, 0.4],
            "by_category": {"jailbreak": {
                "n": 5, "accuracy": 0.6, "cohens_kappa": 0.2,
            }},
        }],
        "rq2": [{
            "judge_model": "judge-70b", "temperature": 0.0, "items": 17,
            "expected_k": 3, "self_agreement": 0.9, "fleiss_kappa": 0.8,
            "self_agreement_ci_95": [0.8, 1.0], "fleiss_kappa_ci_95": [0.5, 1.0],
            "missing_item_groups": 0, "judge_errors_excluded": 1,
        }],
        "rq3": {"reference_judge": "judge-70b", "temperature": 0.0,
                "raw_agreement": 0.7, "keyword_decisive_rate": 0.1,
                "disagreements": [{"response_id": "a"}]},
        "rq4_proxy_error_overlap": {
            "weak_judge": "judge-8b", "temperature": 0.0, "n": 17,
            "keyword_proxy_errors": 3, "weak_judge_errors": 2, "joint_errors": 1,
            "error_overlap_rate": 0.25, "error_overlap_rate_ci_95": [0.1, 0.5],
            "keyword_judge_disagreement": 0.2,
            "keyword_judge_disagreement_ci_95": [0.1, 0.3],
            "interpretation": "proxy only",
        },
    })
    assert "Accuracy 95% CI" in text
    assert "[-0.200, 0.400]" in text
    assert "Missing groups" in text
    assert "κ 95% CI" in text
    assert "Interpretation: proxy only" in text
    assert "0.100, 0.500" in text
    assert "RQ1 category breakdown" in text
    assert "Disagreements recorded" in text
