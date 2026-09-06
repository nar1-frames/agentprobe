from types import SimpleNamespace

import pytest

from research.protocol import load_manifest
from research.run_judges import judge_configs_from_args
from research.gen_corpus import send_prompt


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
