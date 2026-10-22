"""Provider client construction shared by scans and research collection."""

from __future__ import annotations

import os
from typing import Any, Mapping
from urllib.parse import urlparse

from agentprobe.detection import sanitize_error
from agentprobe.replay import ReplayClient


# "replay" serves a local recording and never transmits content, so it is
# deliberately absent here. "http" sends every attack to a deployed agent.
EXTERNAL_PROVIDERS = frozenset({"groq", "openai", "custom", "http"})


def requires_external_consent(provider: str) -> bool:
    """Return whether a provider may transmit study content off-host."""

    return provider in EXTERNAL_PROVIDERS


try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - dependency is declared
    load_dotenv = None

if load_dotenv is not None:
    load_dotenv()


def _validate_base_url(provider: str, base_url: Any) -> None:
    if base_url is None:
        if provider in {"custom", "http"}:
            raise ValueError(f"{provider} provider requires base_url")
        return
    if not isinstance(base_url, str) or not base_url.strip():
        raise ValueError("base_url must be a non-empty HTTP(S) URL")
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("base_url must be a non-empty HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("base_url must not contain embedded credentials")


def build_client(provider_config: Mapping[str, Any]):
    """Build an OpenAI-compatible client with SDK retries disabled."""

    if not isinstance(provider_config, Mapping):
        raise ValueError("provider configuration must be a mapping")
    provider = provider_config.get("provider", "groq")
    if provider == "replay":
        return ReplayClient(provider_config.get("replay_path"))
    base_url = provider_config.get("base_url")
    _validate_base_url(provider, base_url)
    if provider == "http":
        # A deployed agent with its own request shape; see agentprobe/http_target.py.
        from agentprobe.http_target import build_http_target

        return build_http_target(provider_config)
    key_env = provider_config.get("api_key_env")
    if provider in {"groq", "openai"} and not isinstance(key_env, str):
        raise ValueError(f"{provider} provider requires api_key_env")
    api_key = os.environ.get(key_env) if key_env else "ollama"
    timeout = provider_config.get("timeout_seconds", 60)
    client_options = {"timeout": float(timeout), "max_retries": 0}

    if provider == "groq":
        from groq import Groq

        if not api_key:
            raise ValueError("Missing API key for groq provider")
        return Groq(api_key=api_key, **client_options)
    if provider in {"openai", "ollama", "custom"}:
        from openai import OpenAI

        if provider == "openai" and not api_key:
            raise ValueError("Missing API key for openai provider")
        kwargs = {"api_key": api_key or "ollama", **client_options}
        if base_url:
            kwargs["base_url"] = base_url
        elif provider == "ollama":
            kwargs["base_url"] = "http://localhost:11434/v1"
        return OpenAI(**kwargs)
    raise ValueError(f"Unknown provider: '{provider}'")


def preflight_model(client: Any, model: str) -> bool:
    """Verify a provider-listed model before spending prompt-call budget.

    OpenAI-compatible SDKs expose a ``models.list`` endpoint, but not every
    compatible server implements it. If the endpoint is absent, the caller
    continues normally; if it exists, an explicit non-match or provider error
    fails before the first attack request. This catches retired/unauthorized
    model IDs without multiplying a permanent error across a full corpus.
    """

    if not isinstance(model, str) or not model.strip():
        raise ValueError("model must be a non-empty string")
    models_api = getattr(client, "models", None)
    list_models = getattr(models_api, "list", None)
    if not callable(list_models):
        return False
    try:
        listing = list_models()
    except Exception as exc:  # noqa: BLE001 - provider boundary is fail-closed
        raise ValueError(f"model availability preflight failed: {sanitize_error(exc)}") from exc
    data = listing.get("data") if isinstance(listing, Mapping) else getattr(listing, "data", None)
    if data is None:
        # A compatible endpoint returned an unexpected shape. Do not claim
        # availability from an unverifiable response.
        raise ValueError("model availability preflight returned no model list")
    if not isinstance(data, (list, tuple)):
        raise ValueError("model availability preflight returned an invalid model list")
    model_ids = set()
    for item in data:
        item_id = item.get("id") if isinstance(item, Mapping) else getattr(item, "id", None)
        if isinstance(item_id, str):
            model_ids.add(item_id)
    if model not in model_ids:
        raise ValueError(f"model '{model}' is not available from the configured provider")
    return True
