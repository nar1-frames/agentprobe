import pytest
from types import SimpleNamespace

from agentprobe.providers import build_client, preflight_model


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
