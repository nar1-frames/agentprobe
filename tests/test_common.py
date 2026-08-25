"""Tests for research._common plumbing.

Focus: load_env() actually populates os.environ from a .env file (the gap the
README implied worked but didn't), deterministically and without touching the
real environment.
"""
import os

from research._common import load_env, response_id


def test_load_env_reads_key_from_file(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("AGENTPROBE_TEST_KEY=sekret\n")
    monkeypatch.delenv("AGENTPROBE_TEST_KEY", raising=False)
    loaded = load_env(str(env))
    assert loaded == str(env)
    assert os.environ["AGENTPROBE_TEST_KEY"] == "sekret"


def test_load_env_missing_file_is_noop(tmp_path):
    assert load_env(str(tmp_path / "nope.env")) is None


def test_load_env_does_not_override_real_environment(tmp_path, monkeypatch):
    # dotenv's documented behaviour: an already-set var wins over the file.
    env = tmp_path / ".env"
    env.write_text("AGENTPROBE_TEST_KEY2=from_file\n")
    monkeypatch.setenv("AGENTPROBE_TEST_KEY2", "from_env")
    load_env(str(env))
    assert os.environ["AGENTPROBE_TEST_KEY2"] == "from_env"


def test_response_id_is_stable_and_short():
    a = response_id("jailbreak", 0, "llama-3.1-8b-instant")
    b = response_id("jailbreak", 0, "llama-3.1-8b-instant")
    assert a == b and len(a) == 12
    assert a != response_id("jailbreak", 1, "llama-3.1-8b-instant")
