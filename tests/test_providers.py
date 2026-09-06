import pytest
from types import SimpleNamespace

from agentprobe.providers import (
    build_client, preflight_model, requires_external_consent,
)


@pytest.mark.parametrize("provider", ["groq", "openai"])
def test_provider_builder_requires_cloud_api_key_environment(provider):
    with pytest.raises(ValueError, match="requires api_key_env"):
        build_client({"provider": provider, "model": "fixture-model"})


def test_provider_builder_rejects_embedded_endpoint_credentials():
    with pytest.raises(ValueError, match="embedded credentials"):
        build_client({
            "provider": "custom",
            "model": "fixture-model",
            "base_url": "https://user:password@model.example.test/v1",
        })


def test_model_preflight_accepts_a_listed_model():
    class Models:
        @staticmethod
        def list():
            return SimpleNamespace(data=[SimpleNamespace(id="fixture-model")])

    client = SimpleNamespace(models=Models())
    assert preflight_model(client, "fixture-model") is True


def test_model_preflight_rejects_an_unlisted_model_before_prompt_calls():
    class Models:
        @staticmethod
        def list():
            return {"data": [{"id": "other-model"}]}

    with pytest.raises(ValueError, match="not available"):
        preflight_model(SimpleNamespace(models=Models()), "fixture-model")


def test_model_preflight_skips_clients_without_a_models_endpoint():
    assert preflight_model(object(), "fixture-model") is False


@pytest.mark.parametrize("provider", ["groq", "openai", "custom"])
def test_cloud_provider_requires_explicit_content_consent(provider):
    assert requires_external_consent(provider) is True


def test_local_provider_does_not_require_external_content_consent():
    assert requires_external_consent("ollama") is False
