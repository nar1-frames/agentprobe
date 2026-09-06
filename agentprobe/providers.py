"""Provider client construction shared by scans and research collection."""

from __future__ import annotations

import os
from typing import Any, Mapping
from urllib.parse import urlparse


try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - dependency is declared
    load_dotenv = None

if load_dotenv is not None:
    load_dotenv()


def _validate_base_url(provider: str, base_url: Any) -> None:
    if base_url is None:
        if provider == "custom":
            raise ValueError("custom provider requires base_url")
        return
    if not isinstance(base_url, str) or not base_url.strip():
        raise ValueError("base_url must be a non-empty HTTP(S) URL")
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("base_url must be a non-empty HTTP(S) URL")


def build_client(provider_config: Mapping[str, Any]):
    """Build an OpenAI-compatible client with SDK retries disabled."""

    if not isinstance(provider_config, Mapping):
        raise ValueError("provider configuration must be a mapping")
    provider = provider_config.get("provider", "groq")
    base_url = provider_config.get("base_url")
    _validate_base_url(provider, base_url)
    key_env = provider_config.get("api_key_env")
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
