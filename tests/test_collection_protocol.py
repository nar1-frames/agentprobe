from types import SimpleNamespace

import json
import sys
from types import SimpleNamespace

import pytest

from research.protocol import load_manifest
from research.run_judges import judge_configs_from_args, validate_manifest_overrides
import research.gen_corpus as gen_corpus
from research.gen_corpus import generate, resolve_generation_plan, send_prompt
import research.run_judges as run_judges
from research._common import canonical_digest, response_id
from attacks.library import ATTACK_LIBRARY


def test_judge_collection_defaults_to_manifest_matrix():
    manifest = load_manifest()
    args = SimpleNamespace(judges=None, temps=None)
    configs = judge_configs_from_args(
        {"judge": {"provider": "groq", "model": "fallback"}}, args, manifest
    )
    assert [(model, temperature) for _base, model, temperature in configs] == [
        ("openai/gpt-oss-20b", 0.0),
        ("openai/gpt-oss-20b", 0.7),
        ("openai/gpt-oss-120b", 0.0),
        ("openai/gpt-oss-120b", 0.7),
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


def test_corpus_does_not_retry_a_permanent_model_not_found_error():
    calls = []

    class ModelNotFound(Exception):
        status_code = 404

    class Completions:
        def create(self, **_kwargs):
            calls.append(True)
            raise ModelNotFound("model_not_found")

    client = SimpleNamespace(chat=SimpleNamespace(completions=Completions()))
    response, error = send_prompt(
        client, "missing-model", "attack", retries=3, delay=0,
    )
    assert response is None
    assert "model_not_found" in error
    assert len(calls) == 1


def test_corpus_row_records_protocol_and_provider_provenance(tmp_path, monkeypatch):
    calls = []

    class Completions:
        def create(self, **kwargs):
            calls.append(kwargs)
            return SimpleNamespace(
                choices=[SimpleNamespace(
                    message=SimpleNamespace(content="fixture response")
                )]
            )

    monkeypatch.setattr(gen_corpus, "build_client", lambda _config: SimpleNamespace(
        chat=SimpleNamespace(completions=Completions())
    ))
    monkeypatch.setattr(gen_corpus, "iter_attacks", lambda: iter([
        ("jailbreak", 0, {
            "prompt": "fixture attack", "severity": "HIGH",
            "description": "fixture",
        }),
    ]))
    monkeypatch.setattr(gen_corpus.time, "sleep", lambda _seconds: None)
    records = {}
    path = tmp_path / "corpus.jsonl"
    generate(
        {"provider": "ollama", "model": "target-3b", "base_url": "http://localhost/v1"},
        "target-3b", str(path), 512, 0.0, 0, retries=0, retry_delay=0,
        records_by_id=records, protocol_manifest_sha256="a" * 64,
    )
    row = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert row["protocol_manifest_sha256"] == "a" * 64
    assert len(row["target_config_sha256"]) == 64
    assert row["target_provider"] == "ollama"
    assert row["collected_at"].endswith("Z")
    assert calls[0]["temperature"] == 0.0


def test_corpus_generation_defaults_to_manifest_scope_and_settings():
    manifest = load_manifest()
    models, max_tokens, temperature = resolve_generation_plan(
        {"model": "wrong-config-model", "provider": "groq",
         "max_tokens": 99, "temperature": 0.7},
        manifest=manifest,
    )
    assert models == manifest["corpus"]["target_models"]
    assert max_tokens == manifest["corpus"]["target_max_tokens"]
    assert temperature == manifest["corpus"]["target_temperature"]


def test_corpus_generation_rejects_manifest_deviation_before_provider_calls():
    manifest = load_manifest()
    with pytest.raises(ValueError, match="--target-temperature must match"):
        resolve_generation_plan(
            {"model": "target"}, temperature_arg=0.7, manifest=manifest,
        )


def test_judge_collection_rejects_manifest_matrix_deviation_before_provider_calls():
    manifest = load_manifest()
    args = SimpleNamespace(judges="only-one", temps=None, k=None)
    with pytest.raises(ValueError, match="--judges must match"):
        validate_manifest_overrides(args, manifest)


def test_judge_collection_rejects_manifest_repeat_deviation_before_provider_calls():
    manifest = load_manifest()
    args = SimpleNamespace(judges=None, temps=None, k=1)
    with pytest.raises(ValueError, match="--k must match"):
        validate_manifest_overrides(args, manifest)


def test_judge_rows_record_the_frozen_corpus_digest(tmp_path, monkeypatch):
    corpus = [{
        "response_id": response_id("jailbreak", 0, "target-8b"),
        "category": "jailbreak",
        "attack_index": 0,
        "target_model": "target-8b",
        "attack_prompt": ATTACK_LIBRARY["jailbreak"][0]["prompt"],
        "severity": ATTACK_LIBRARY["jailbreak"][0]["severity"],
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
    assert row["judge_max_tokens"] == 120
    assert len(row["judge_config_sha256"]) == 64
    assert row["protocol_manifest_sha256"] is None


def test_corpus_fail_on_error_preserves_artifact_and_returns_status_three(tmp_path, monkeypatch):
    monkeypatch.setattr(gen_corpus, "load_config", lambda _path: {
        "target": {"provider": "ollama", "model": "target-3b",
                   "base_url": "http://localhost/v1"},
        "scan": {"rate_limit_seconds": 0, "retries": 0, "retry_delay_seconds": 0},
    })
    monkeypatch.setattr(gen_corpus, "iter_attacks", lambda: iter([
        ("jailbreak", 0, {"prompt": "fixture attack", "severity": "HIGH"}),
    ]))
    monkeypatch.setattr(gen_corpus, "build_client", lambda _config: SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(
            create=lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("offline"))
        ))
    ))
    monkeypatch.setattr(gen_corpus.time, "sleep", lambda _seconds: None)
    output_path = tmp_path / "corpus.jsonl"
    monkeypatch.setattr(sys, "argv", [
        "gen_corpus", "--config", "unused.yaml", "--models", "target-3b",
        "--manifest", "", "--out", str(output_path), "--overwrite", "--fail-on-error",
    ])

    with pytest.raises(SystemExit) as exc_info:
        gen_corpus.main()
    assert exc_info.value.code == 3
    assert json.loads(output_path.read_text(encoding="utf-8"))["error"]


def test_judge_fail_on_error_preserves_evidence_and_returns_status_three(tmp_path, monkeypatch):
    corpus = [{
        "response_id": response_id("jailbreak", 0, "target-8b"),
        "category": "jailbreak", "attack_index": 0, "target_model": "target-8b",
        "attack_prompt": ATTACK_LIBRARY["jailbreak"][0]["prompt"],
        "severity": ATTACK_LIBRARY["jailbreak"][0]["severity"], "response": "response",
    }]
    corpus_path = tmp_path / "corpus.jsonl"
    corpus_path.write_text(json.dumps(corpus[0]) + "\n")
    output_path = tmp_path / "judgements.jsonl"
    monkeypatch.setattr(run_judges, "load_config", lambda _path: {
        "judge": {"provider": "ollama", "model": "fallback", "max_tokens": 120},
        "scan": {"rate_limit_seconds": 0, "retries": 0, "retry_delay_seconds": 0},
    })
    monkeypatch.setattr(run_judges, "build_client", lambda _config: object())
    monkeypatch.setattr(run_judges, "llm_judge", lambda *args, **kwargs: SimpleNamespace(
        judge_verdict="UNKNOWN", verdict="SUSPICIOUS", reason="failed", raw="",
        error="offline",
    ))
    monkeypatch.setattr(run_judges.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(sys, "argv", [
        "run_judges", "--config", "unused.yaml", "--corpus", str(corpus_path),
        "--out", str(output_path), "--judges", "judge-8b", "--temps", "0", "--k", "1",
        "--manifest", "", "--fail-on-error",
    ])

    with pytest.raises(SystemExit) as exc_info:
        run_judges.main()
    assert exc_info.value.code == 3
    assert json.loads(output_path.read_text(encoding="utf-8"))["error"] == "offline"
