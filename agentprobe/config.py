"""Validated configuration for scanner and research entry points.

Configuration is an input boundary: rejecting an invalid scan before creating
clients is safer than discovering a bad provider, category, or rate limit in
the middle of an expensive run. This module stays dependency-light so every
entry point shares the same contract.
"""

from copy import deepcopy
import math
import os
import re
from typing import Any, Mapping
from urllib.parse import urlparse

import yaml


SUPPORTED_PROVIDERS = frozenset({"groq", "openai", "ollama", "custom", "http", "replay"})
VALID_CATEGORIES = frozenset({
    "jailbreak", "data_extraction", "privilege_escalation",
    "social_engineering", "role_confusion", "indirect_injection",
    "context_manipulation", "tool_misuse",
})
VALID_SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
_CATEGORY_NAME = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
VALID_REASONING_EFFORTS = frozenset({
    "none", "default", "minimal", "low", "medium", "high", "xhigh", "max",
})


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be a mapping")
    return value


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    """Validate an integer without silently truncating floats or booleans."""

    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be an integer")
    if not math.isfinite(number) or number != int(number):
        raise ValueError(f"{name} must be an integer")
    result = int(number)
    if result < minimum or result > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return result


def _positive_number(value: Any, name: str, maximum=None) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be numeric")
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be numeric")
    if not math.isfinite(number) or number < 0 or (maximum is not None and number > maximum):
        limit = f" and <= {maximum:g}" if maximum is not None else ""
        raise ValueError(f"{name} must be >= 0{limit}")
    return number


def _validate_model_block(config: Mapping[str, Any], name: str) -> float:
    block = _mapping(config.get(name), name)
    provider = block.get("provider", "groq")
    if not isinstance(provider, str) or provider not in SUPPORTED_PROVIDERS:
        raise ValueError(
            f"{name}.provider must be one of {', '.join(sorted(SUPPORTED_PROVIDERS))}"
        )
    model = block.get("model")
    if not isinstance(model, str) or not model.strip():
        raise ValueError(f"{name}.model must be a non-empty string")
    if "api_key" in block:
        raise ValueError(f"{name}.api_key is not allowed; use api_key_env")
    key_env = block.get("api_key_env")
    if key_env is not None and (not isinstance(key_env, str) or not key_env.strip()):
        raise ValueError(f"{name}.api_key_env must be a non-empty string or null")
    if provider in {"groq", "openai"} and not isinstance(key_env, str):
        raise ValueError(f"{name}.api_key_env is required for {provider} provider")
    replay_path = block.get("replay_path")
    if provider == "replay":
        if not isinstance(replay_path, str) or not replay_path.strip():
            raise ValueError(f"{name}.replay_path is required for replay provider")
    elif replay_path is not None:
        # Ignoring it would silently send a "replayed" scan to a live provider.
        raise ValueError(f"{name}.replay_path is only valid with the replay provider")
    if provider == "http":
        if name != "target":
            raise ValueError(
                f"{name}.provider http is only valid for the target; the judge "
                "must be a model you control"
            )
        if "strength_rank" not in block:
            raise ValueError(
                "target.strength_rank is required for the http provider: a deployed "
                "agent does not reveal its model, so the judge-strength gate needs "
                "an explicit rank for both target and judge"
            )
        from agentprobe.http_target import validate_http_block

        validate_http_block(block.get("http"), f"{name}.http")
    elif "http" in block:
        raise ValueError(f"{name}.http is only valid with the http provider")
    base_url = block.get("base_url")
    if base_url is None:
        if provider in {"custom", "http"}:
            raise ValueError(f"{name}.base_url is required for {provider} provider")
    elif not isinstance(base_url, str) or not base_url.strip():
        raise ValueError(f"{name}.base_url must be a non-empty HTTP(S) URL")
    else:
        parsed_url = urlparse(base_url)
        if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
            raise ValueError(f"{name}.base_url must be a non-empty HTTP(S) URL")
        if parsed_url.username is not None or parsed_url.password is not None:
            raise ValueError(f"{name}.base_url must not contain embedded credentials")
    timeout = _positive_number(
        block.get("timeout_seconds", 60), f"{name}.timeout_seconds", 3600
    )
    if timeout <= 0:
        raise ValueError(f"{name}.timeout_seconds must be > 0")
    if "strength_rank" in block:
        try:
            rank = float(block["strength_rank"])
        except (TypeError, ValueError):
            raise ValueError(f"{name}.strength_rank must be numeric")
        if not math.isfinite(rank) or rank < 0:
            raise ValueError(f"{name}.strength_rank must be >= 0")
    if "reasoning_effort" in block:
        effort = block["reasoning_effort"]
        if not isinstance(effort, str) or effort not in VALID_REASONING_EFFORTS:
            raise ValueError(
                f"{name}.reasoning_effort must be one of "
                f"{', '.join(sorted(VALID_REASONING_EFFORTS))}"
            )
    if "system_prompt" in block and not isinstance(block["system_prompt"], str):
        raise ValueError(f"{name}.system_prompt must be a string")
    return timeout


def validate_config(config: Mapping[str, Any]) -> dict:
    """Validate and return an independent, JSON/YAML-shaped config copy."""

    config = _mapping(config, "config")
    target_timeout = _validate_model_block(config, "target")
    judge_timeout = _validate_model_block(config, "judge")

    scan = _mapping(config.get("scan", {}), "scan")
    categories = scan.get("categories", "all")
    if categories != "all":
        if not isinstance(categories, (list, tuple)) or not categories:
            raise ValueError("scan.categories must be 'all' or a non-empty list")
        if not all(isinstance(category, str) for category in categories):
            raise ValueError("scan.categories entries must be strings")
        # Which categories exist depends on the loaded attack packs, so this
        # checks the name shape; selection rejects a category no pack provides.
        unknown = sorted(c for c in categories if not _CATEGORY_NAME.match(c))
        if unknown:
            raise ValueError(f"scan.categories contains unknown values: {', '.join(unknown)} "
                             "(category names are lowercase snake_case)")
    packs = config.get("packs")
    if packs is not None:
        if (not isinstance(packs, (list, tuple)) or not packs or len(packs) > 20
                or not all(isinstance(spec, str) and spec.strip() for spec in packs)):
            raise ValueError("packs must be a list of 1 to 20 pack names or paths")
    if config.get("packs_trust") is not None:
        from agentprobe.signing import SignatureError, trust_policy

        try:
            trust_policy(config["packs_trust"])
        except SignatureError as exc:
            raise ValueError(str(exc)) from exc
    severity = scan.get("severity_filter")
    if severity is not None and severity not in VALID_SEVERITIES:
        raise ValueError(
            f"scan.severity_filter must be one of {', '.join(VALID_SEVERITIES)} or null"
        )
    rate_limit = _positive_number(
        scan.get("rate_limit_seconds", 1), "scan.rate_limit_seconds", 3600
    )
    retry_values = {}
    for key, default, maximum in (
        ("retries", 2, 10),
        ("retry_delay_seconds", 3, 3600),
    ):
        value = scan.get(key, default)
        retry_values[key] = (
            _integer(value, f"scan.{key}", 0, maximum)
            if key == "retries"
            else _positive_number(value, f"scan.{key}", maximum)
        )
    record_path = scan.get("record_replay_path")
    if record_path is not None and (not isinstance(record_path, str) or not record_path.strip()):
        raise ValueError("scan.record_replay_path must be a non-empty path or null")

    target = config["target"]
    max_tokens_int = _integer(
        target.get("max_tokens", 512), "target.max_tokens", 1, 131072
    )
    target_temperature = _positive_number(
        target.get("temperature", 0.0), "target.temperature", 2
    )
    judge = config["judge"]
    judge_max_tokens_int = _integer(
        judge.get("max_tokens", 120), "judge.max_tokens", 1, 131072
    )
    judge_temperature = _positive_number(
        judge.get("temperature", 0.1), "judge.temperature", 2
    )

    output = _mapping(config.get("output", {}), "output")
    report_dir = output.get("report_dir", "reports")
    if not isinstance(report_dir, str) or not report_dir.strip():
        raise ValueError("output.report_dir must be a non-empty path")
    report_format = output.get("report_format", "both")
    if report_format not in {"html", "json", "both"}:
        raise ValueError("output.report_format must be html, json, or both")

    normalized = deepcopy(dict(config))
    if target.get("provider") == "http":
        from agentprobe.http_target import validate_http_block

        normalized["target"]["http"] = validate_http_block(target.get("http"), "target.http")
    normalized.setdefault("scan", {})["rate_limit_seconds"] = rate_limit
    normalized["scan"]["retries"] = int(retry_values["retries"])
    normalized["scan"]["retry_delay_seconds"] = retry_values["retry_delay_seconds"]
    normalized["target"]["max_tokens"] = max_tokens_int
    normalized["target"]["temperature"] = target_temperature
    normalized["target"]["timeout_seconds"] = target_timeout
    normalized["judge"]["max_tokens"] = judge_max_tokens_int
    normalized["judge"]["temperature"] = judge_temperature
    normalized["judge"]["timeout_seconds"] = judge_timeout
    return normalized


def load_config(path="config.yaml") -> dict:
    """Load YAML and validate it before callers create clients or scan."""

    if not os.path.exists(path):
        raise FileNotFoundError(f"Configuration file not found: {path}")
    with open(path, encoding="utf-8") as f:
        loaded = yaml.safe_load(f) or {}
    return validate_config(loaded)


def client_config(block: Mapping[str, Any], config_path: str) -> dict:
    """Return a provider block for build_client with input paths made absolute.

    A replay recording travels with the config that names it, so a relative
    ``replay_path`` means "next to the config file", not "wherever the command
    runs". The validated config keeps the path as written, so its digest does
    not depend on where the file sits on disk. Output paths (report_dir,
    record_replay_path, checkpoints) stay relative to the working directory, so
    scan output never lands inside an installed package.
    """

    resolved = dict(block)
    replay_path = resolved.get("replay_path")
    if replay_path and not os.path.isabs(replay_path):
        base = os.path.dirname(os.path.abspath(config_path))
        resolved["replay_path"] = os.path.join(base, replay_path)
    return resolved
