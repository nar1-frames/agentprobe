import pytest

from types import SimpleNamespace

from research.label import load_existing, pick_subset, validate_labeling_options
from research.protocol import expected_second_label_ids


def _corpus(order):
    return [
        {
            "response_id": response_id,
            "category": "fixture",
            "attack_index": index,
            "response": response_id,
        }
        for index, response_id in enumerate(order, start=1)
    ]


def test_second_label_subset_matches_manifest_assignment():
    corpus = _corpus(["zulu", "alpha", "echo", "bravo", "delta", "charlie"])
    selected = pick_subset(corpus, 0.3, 42)
    expected = expected_second_label_ids(corpus, 0.3, 42)
    assert {row["response_id"] for row in selected} == expected


def test_second_label_subset_is_invariant_to_corpus_row_order():
    first = _corpus(["zulu", "alpha", "echo", "bravo", "delta", "charlie"])
    second = list(reversed(first))
    assert {row["response_id"] for row in pick_subset(first, 0.5, 42)} == {
        row["response_id"] for row in pick_subset(second, 0.5, 42)
    }


def test_label_resume_rejects_evidence_from_a_different_corpus(tmp_path):
    path = tmp_path / "labels.csv"
    path.write_text(
        "response_id,labeler,label,note,category,target_model,corpus_sha256\n"
        f"a,ren,REFUSED,,,target,{'a' * 64}\n"
    )
    with pytest.raises(ValueError, match="corpus_sha256"):
        load_existing(str(path), "ren", "b" * 64)


def test_manifest_labeling_rejects_keyword_display_and_subset_deviation():
    from research.protocol import load_manifest

    manifest = load_manifest()
    with pytest.raises(ValueError, match="show-hits is disabled"):
        validate_labeling_options(
            SimpleNamespace(show_hits=True, subset=None, seed=None),
            manifest, "ren",
        )
    with pytest.raises(ValueError, match="--subset must match"):
        validate_labeling_options(
            SimpleNamespace(show_hits=False, subset=0.5, seed=None),
            manifest, "friend",
        )
