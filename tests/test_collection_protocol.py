from types import SimpleNamespace

import json
import sys
from types import SimpleNamespace

import pytest

from research.protocol import load_manifest
from research.run_judges import judge_configs_from_args
from research.gen_corpus import send_prompt
import research.run_judges as run_judges
from research._common import canonical_digest


def test_judge_collection_defaults_to_manifest_matrix():
    manifest = load_manifest()
    args = SimpleNamespace(judges=None, temps=None)
    configs = judge_configs_from_args(
        {"judge": {"provider": "ollama", "model": "fallback"}}, args, manifest
    )
    assert [(model, temperature) for _base, model, temperature in configs] == [
        ("llama-3.1-8b-instant", 0.0),
        ("llama-3.1-8b-instant", 0.7),
        ("llama-3.3-70b-versatile", 0.0),
        ("llama-3.3-70b-versatile", 0.7),
    ]


def test_judge_collection_rejects_out_of_range_temperature():
    args = SimpleNamespace(judges="judge", temps="nan")
    with pytest.raises(ValueError, match="between 0 and 2"):
        judge_configs_from_args(
            {"judge": {"provider": "ollama", "model": "fallback"}}, args
        )


def test_corpus_target_request_receives_explicit_temperature():
    calls = []

    class Completions:
        def create(self, **kwargs):
            calls.append(kwargs)
            return SimpleNamespace(
                choices=[SimpleNamespace(
                    message=SimpleNamespace(content="fixture response")
                )]
            )

    client = SimpleNamespace(chat=SimpleNamespace(completions=Completions()))
    response, error = send_prompt(
        client, "target", "attack", max_tokens=512, temperature=0.0,
        retries=0, delay=0,
    )
    assert response == "fixture response"
    assert error is None
    assert calls[0]["temperature"] == 0.0


def test_judge_rows_record_the_frozen_corpus_digest(tmp_path, monkeypatch):
    corpus = [{
        "response_id": "response-1",
        "category": "fixture",
        "attack_index": 0,
        "target_model": "target-8b",
        "attack_prompt": "attack",
        "response": "response",
    }]
    corpus_path = tmp_path / "corpus.jsonl"
    corpus_path.write_text("\n".join(json.dumps(row) for row in corpus) + "\n")
    output_path = tmp_path / "judgements.jsonl"

    monkeypatch.setattr(run_judges, "load_config", lambda _path: {
        "judge": {"provider": "ollama", "model": "fallback", "max_tokens": 120},
        "scan": {"rate_limit_seconds": 0, "retries": 0, "retry_delay_seconds": 0},
    })
    monkeypatch.setattr(run_judges, "build_client", lambda _config: object())
    monkeypatch.setattr(run_judges, "llm_judge", lambda *args, **kwargs: SimpleNamespace(
        judge_verdict="REFUSED", verdict="SAFE", reason="fixture", raw="raw", error=None,
    ))
    monkeypatch.setattr(run_judges.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(sys, "argv", [
        "run_judges", "--config", "unused.yaml", "--corpus", str(corpus_path),
        "--out", str(output_path), "--judges", "judge-8b", "--temps", "0",
        "--k", "1", "--manifest", "",
    ])

    run_judges.main()
    row = json.loads(output_path.read_text(encoding="utf-8").splitlines()[0])
    assert row["corpus_sha256"] == canonical_digest(corpus)
