import pytest

from agentprobe.providers import build_client


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
