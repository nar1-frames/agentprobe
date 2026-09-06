import json

import pytest

from research.protocol import expected_configs, expected_second_label_ids, load_manifest


def test_checked_in_study_manifest_is_valid_and_explicit():
    manifest = load_manifest()
    assert manifest["protocol_version"] == "1.1"
    assert manifest["repeats"] == 5
    assert manifest["corpus"]["target_models"] == ["llama-3.1-8b-instant"]
    assert manifest["corpus"]["target_provider"] == "groq"
    assert manifest["corpus"]["target_temperature"] == 0.0
    assert manifest["corpus"]["target_max_tokens"] == 512
    assert manifest["judge_provider"] == "groq"
    assert manifest["judge_max_tokens"] == 120
    assert len(manifest["labeling_guide_sha256"]) == 64
    assert expected_configs(manifest) == [
        "llama-3.1-8b-instant@0",
        "llama-3.1-8b-instant@0.7",
        "llama-3.3-70b-versatile@0",
        "llama-3.3-70b-versatile@0.7",
    ]


def test_manifest_rejects_duplicate_judge_conditions(tmp_path):
    manifest = {
        "protocol_version": "1.1",
        "attack_library_sha256": "0" * 64,
        "judge_prompt_version": "2.0",
        "judge_prompt_sha256": "1" * 64,
        "labeling_guide_sha256": "2" * 64,
        "corpus": {
            "target_models": ["target"], "target_provider": "ollama",
            "responses_per_target": 1,
            "target_temperature": 0.0, "target_max_tokens": 512,
        },
        "judges": [
            {"model": "judge", "temperature": 0},
            {"model": "judge", "temperature": 0},
        ],
        "analysis": {
            "reference": {"model": "judge", "temperature": 0},
            "weak": {"model": "judge", "temperature": 0},
        },
        "judge_provider": "ollama", "judge_max_tokens": 120,
        "repeats": 2,
        "labels": {
            "primary": "one", "second": "two", "second_overlap_fraction": 0.3,
            "second_subset_seed": 42,
            "vocabulary": ["COMPLIED", "PARTIAL", "REFUSED"],
        },
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="duplicate judge condition"):
        load_manifest(path)


def test_second_label_subset_is_independent_of_corpus_row_order():
    corpus = [{"response_id": response_id} for response_id in ("c", "a", "b", "d")]
    reversed_corpus = list(reversed(corpus))
    assert expected_second_label_ids(corpus, 0.5, 42) == expected_second_label_ids(
        reversed_corpus, 0.5, 42
    )
