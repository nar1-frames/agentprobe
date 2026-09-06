"""Shared plumbing for the research pipeline: config, clients, JSONL I/O.

Kept tiny and dependency-light on purpose — the pipeline scripts should read
like the method section of the paper, not like a framework.
"""
import json
import os
import sys
import hashlib
import tempfile

from agentprobe.config import load_config as _load_validated_config
from agentprobe.providers import build_client

# Make the repo root importable whether you run `python research/foo.py`
# or `python -m research.foo`.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def _reject_json_constant(value):
    raise ValueError(f"non-standard JSON constant {value}")


def load_env(path=None):
    """Load KEY=VALUE pairs from a .env file into os.environ.

    The README tells users to put GROQ_API_KEY in .env, but nothing read it —
    build_client() looked straight at os.environ. This closes that gap so the
    pipeline works as documented. It is a no-op if python-dotenv isn't
    installed or the file is missing, and (per dotenv's default) it never
    overrides variables already set in the real environment.

    Returns the path actually loaded, or None.
    """
    path = path or os.path.join(_ROOT, ".env")
    try:
        from dotenv import load_dotenv
    except ImportError:
        return None
    if os.path.exists(path):
        load_dotenv(path)
        return path
    return None


# Auto-load the repo-root .env on import so every pipeline entry point
# (gen_corpus, run_judges, analyze) picks up GROQ_API_KEY without ceremony.
load_env()


def load_config(path="config.yaml"):
    return _load_validated_config(path)


def response_id(category, attack_index, target_model):
    """Stable ID for a (attack, target-model) response.

    Deterministic so re-runs, judge passes, and human labels all key on the
    same identifier without a shared counter.
    """
    raw = f"{category}|{attack_index}|{target_model}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]


def canonical_digest(records):
    """SHA-256 of JSON records in response-id order for artifact provenance."""

    canonical = json.dumps(
        sorted(
            records,
            key=lambda row: row.get("response_id", "")
            if isinstance(row, dict) else "",
        ),
        sort_keys=True, ensure_ascii=False, separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def write_jsonl(path, records):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".agentprobe-jsonl-", suffix=".jsonl", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for record in records:
                f.write(json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def append_jsonl(path, record):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n")
        f.flush()
        os.fsync(f.fileno())


def read_jsonl(path):
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(
                        line,
                        parse_constant=_reject_json_constant,
                    ))
                except (json.JSONDecodeError, ValueError) as exc:
                    raise ValueError(
                        f"{path}:{line_number}: invalid JSONL record: {exc}"
                    ) from exc
    return out
