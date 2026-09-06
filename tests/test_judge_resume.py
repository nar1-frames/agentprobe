import json

from research.run_judges import load_done_keys, repair_error_rows


def test_resume_ignores_failed_rows_until_explicit_repair(tmp_path):
    path = tmp_path / "judgements.jsonl"
    good = {
        "response_id": "ok", "judge_model": "judge", "temperature": 0,
        "run_idx": 0, "verdict": "SAFE",
    }
    failed = {
        "response_id": "failed", "judge_model": "judge", "temperature": 0,
        "run_idx": 0, "verdict": "SUSPICIOUS", "error": "429",
    }
    path.write_text("\n".join(json.dumps(row) for row in (good, failed)) + "\n")

    assert load_done_keys(path) == {("ok", "judge", 0.0, 0)}
    repaired, archive = repair_error_rows(path)

    assert repaired == 1
    assert archive.endswith(".errors.jsonl")
    assert load_done_keys(path) == {("ok", "judge", 0.0, 0)}
    assert [json.loads(line)["response_id"] for line in path.read_text().splitlines()] == ["ok"]
    assert json.loads((tmp_path / "judgements.jsonl.errors.jsonl").read_text())["response_id"] == "failed"


def test_resume_rejects_evidence_from_a_different_corpus(tmp_path):
    path = tmp_path / "judgements.jsonl"
    path.write_text(json.dumps({
        "response_id": "ok", "judge_model": "judge", "temperature": 0,
        "run_idx": 0, "verdict": "SAFE", "corpus_sha256": "a" * 64,
    }) + "\n")

    try:
        load_done_keys(path, "b" * 64)
    except ValueError as exc:
        assert "corpus_sha256" in str(exc)
    else:
        raise AssertionError("resume accepted evidence from a different corpus")
