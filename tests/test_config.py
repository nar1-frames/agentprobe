import pytest

from agentprobe.config import validate_config


def _config():
    return {
        "target": {"provider": "ollama", "model": "llama3.2:3b"},
        "judge": {"provider": "ollama", "model": "llama3.1:8b"},
        "scan": {"categories": ["jailbreak"], "rate_limit_seconds": 0},
        "output": {"report_dir": "reports", "report_format": "both"},
    }


def test_config_validation_normalizes_safe_defaults():
    original = _config()
    normalized = validate_config(original)
    assert normalized["target"]["max_tokens"] == 512
    assert normalized["target"]["temperature"] == 0.0
    assert normalized["judge"]["max_tokens"] == 120
    assert normalized["judge"]["temperature"] == 0.1
    assert normalized["scan"]["rate_limit_seconds"] == 0.0
    assert normalized["target"]["timeout_seconds"] == 60.0
    assert normalized["target"] is not original["target"]


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("target", "provider"), "unknown", "provider"),
        (("target", "model"), "", "model"),
        (("scan", "categories"), ["not-a-category"], "unknown"),
        (("scan", "severity_filter"), "EXTREME", "severity_filter"),
        (("scan", "rate_limit_seconds"), -1, "rate_limit_seconds"),
        (("target", "timeout_seconds"), 0, "timeout_seconds"),
        (("target", "max_tokens"), 0, "max_tokens"),
        (("output", "report_format"), "txt", "report_format"),
    ],
)
def test_config_validation_rejects_invalid_values(path, value, message):
    config = _config()
    config.setdefault(path[0], {})[path[1]] = value
    with pytest.raises(ValueError, match=message):
        validate_config(config)


def test_config_rejects_literal_api_keys():
    config = _config()
    config["target"]["api_key"] = "must-not-be-here"
    with pytest.raises(ValueError, match="api_key_env"):
        validate_config(config)


def test_config_requires_and_validates_custom_provider_endpoint():
    config = _config()
    config["target"] = {"provider": "custom", "model": "target-3b"}
    with pytest.raises(ValueError, match="base_url is required"):
        validate_config(config)
    config["target"]["base_url"] = "not-a-url"
    with pytest.raises(ValueError, match=r"HTTP\(S\) URL"):
        validate_config(config)
    config["target"]["base_url"] = "https://model.example.test/v1"
    assert validate_config(config)["target"]["base_url"] == "https://model.example.test/v1"


def test_config_accepts_explicit_strength_rank_and_retry_settings():
    config = _config()
    config["target"]["strength_rank"] = 1
    config["judge"]["strength_rank"] = 2
    config["scan"].update({"retries": 4, "retry_delay_seconds": 0})
    normalized = validate_config(config)
    assert normalized["scan"]["retries"] == 4
    assert normalized["scan"]["retry_delay_seconds"] == 0


@pytest.mark.parametrize(
    ("section", "key", "value"),
    [
        ("target", "max_tokens", 1.5),
        ("target", "max_tokens", True),
        ("judge", "max_tokens", 1.5),
        ("judge", "max_tokens", True),
        ("scan", "retries", 1.5),
        ("scan", "retries", True),
    ],
)
def test_config_does_not_silently_truncate_integer_settings(section, key, value):
    config = _config()
    config[section][key] = value
    with pytest.raises(ValueError, match="integer"):
        validate_config(config)


def test_config_rejects_unhashable_provider_value():
    config = _config()
    config["target"]["provider"] = ["ollama"]
    with pytest.raises(ValueError, match="provider"):
        validate_config(config)


@pytest.mark.parametrize("section", ["target", "judge"])
def test_config_rejects_invalid_model_temperature(section):
    config = _config()
    config[section]["temperature"] = 2.1
    with pytest.raises(ValueError, match="temperature"):
        validate_config(config)


def test_config_preserves_explicit_judge_runtime_settings():
    config = _config()
    config["target"]["temperature"] = 0.2
    config["judge"].update({"temperature": 0.7, "max_tokens": 256})
    normalized = validate_config(config)
    assert normalized["target"]["temperature"] == 0.2
    assert normalized["judge"]["temperature"] == 0.7
    assert normalized["judge"]["max_tokens"] == 256
