"""Machine-readable scan artifacts.

The HTML report is optimized for a human review. This module provides the
stable JSON boundary used by CI, later statistical analysis, and downstream
tools. The tuple shape is accepted for backwards compatibility with the v1.1
scanner while the serialized schema is explicit and self-describing.
"""

import datetime as _datetime
import hashlib
import json
import os
import re
import tempfile
import uuid
from collections import Counter, defaultdict
from typing import Any, Dict, Mapping

from agentprobe.events import EVENT_SCHEMA_VERSION, validate_events


SCHEMA_VERSION = "1.0"
HARNESS_SCHEMA_VERSION = "1.4"
TOOL_VERSION = "1.7.0"
VERDICTS = ("VULNERABLE", "PARTIAL", "SAFE", "SUSPICIOUS")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def _utc_now():
    return _datetime.datetime.now(_datetime.timezone.utc).replace(microsecond=0).isoformat()


def safe_filename_component(value):
    """Keep provider-controlled model IDs inside the configured report directory."""

    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value)).strip("._")
    return safe or "model"


def _digest(value):
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def attack_library_digest(attack_library):
    """Digest attack content, excluding runtime-only selection metadata."""

    canonical = {
        category: [
            {key: value for key, value in attack.items() if key != "_library_index"}
            for attack in attacks
        ]
        for category, attacks in attack_library.items()
    }
    return _digest(canonical)


# Kept as a private compatibility alias for older internal callers.
_attack_library_digest = attack_library_digest


def build_run_metadata(target_model, judge_model, target_provider=None,
                       judge_provider=None, config=None, attack_library=None,
                       run_id=None, judge_prompt_version=None,
                       judge_prompt_sha256=None, attack_pack=None):
    """Create provenance metadata without copying credentials into reports."""

    metadata = {
        "run_id": run_id or uuid.uuid4().hex,
        "tool_version": TOOL_VERSION,
        "target_model": target_model,
        "judge_model": judge_model,
    }
    if target_provider:
        metadata["target_provider"] = target_provider
    if judge_provider:
        metadata["judge_provider"] = judge_provider
    if judge_prompt_version:
        metadata["judge_prompt_version"] = judge_prompt_version
    if judge_prompt_sha256:
        metadata["judge_prompt_sha256"] = judge_prompt_sha256
    if config is not None:
        metadata["config_sha256"] = _digest(config)
        # Keep the settings that materially affect model behavior visible in
        # the artifact, while excluding credentials and arbitrary config data.
        for role, prefix in (("target", "target"), ("judge", "judge")):
            block = config.get(role) if isinstance(config, Mapping) else None
            if not isinstance(block, Mapping):
                continue
            for key in ("temperature", "max_tokens", "reasoning_effort"):
                if key in block:
                    metadata[f"{prefix}_{key}"] = block[key]
            if "system_prompt" in block and isinstance(block["system_prompt"], str):
                metadata[f"{prefix}_system_prompt_sha256"] = hashlib.sha256(
                    block["system_prompt"].encode("utf-8")
                ).hexdigest()
        scan = config.get("scan") if isinstance(config, Mapping) else None
        if isinstance(scan, Mapping):
            for key in ("retries", "retry_delay_seconds", "rate_limit_seconds"):
                if key in scan:
                    metadata[f"scan_{key}"] = scan[key]
    if attack_library is not None:
        metadata["attack_library_sha256"] = attack_library_digest(attack_library)
    if attack_pack is not None:
        # Imported here because the attack-pack module itself builds on this one.
        from agentprobe.attackpack import attack_pack_digest, validate_attack_pack

        validate_attack_pack(attack_pack)
        metadata["attack_pack_schema_version"] = attack_pack["schema_version"]
        metadata["attack_pack_sha256"] = attack_pack_digest(attack_pack)
    return metadata


def build_json_report(scan_results, target_model, judge_model, generated_at=None,
                      metadata=None):
    """Convert legacy scan tuples into a versioned, JSON-serializable report."""

    rows = []
    by_category = defaultdict(lambda: Counter())
    verdict_counts = Counter()
    finding_counts = Counter()
    error_count = 0

    for category, results in scan_results.items():
        for position, row in enumerate(results, start=1):
            attack, response, verdict, finding_severity, reason, method = row
            attack_index = attack.get("_library_index", position)
            is_error = method in {"target-error", "judge-error"}
            error_count += int(is_error)
            verdict_counts[verdict] += 1
            by_category[category]["total"] += 1
            by_category[category]["errors"] += int(is_error)
            by_category[category][verdict.lower()] += 1
            if finding_severity:
                finding_counts[finding_severity] += 1

            rows.append({
                "attack_id": f"{category}:{attack_index}",
                "category": category,
                "attack_index": attack_index,
                "attack_severity": attack.get("severity"),
                "prompt": attack.get("prompt", ""),
                "description": attack.get("description", ""),
                "response": response,
                "verdict": verdict,
                "finding_severity": finding_severity,
                "reason": reason,
                "method": method,
                "status": "error" if is_error else "complete",
            })

    total = len(rows)
    run = dict(metadata or {})
    run.setdefault("run_id", uuid.uuid4().hex)
    run.setdefault("tool_version", TOOL_VERSION)
    run.setdefault("target_model", target_model)
    run.setdefault("judge_model", judge_model)
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": "agentprobe",
        "generated_at": generated_at or _utc_now(),
        "target_model": target_model,
        "judge_model": judge_model,
        "run": run,
        "summary": {
            "total_attacks": total,
            "scorable_attacks": total - error_count,
            "verdicts": {verdict: verdict_counts[verdict] for verdict in VERDICTS},
            "findings_by_severity": {
                severity: finding_counts[severity] for severity in SEVERITIES
            },
            "operational_errors": error_count,
        },
        "categories": {
            category: {
                "total": stats["total"],
                "operational_errors": stats["errors"],
                "verdicts": {verdict: stats[verdict.lower()] for verdict in VERDICTS},
            }
            for category, stats in sorted(by_category.items())
        },
        "results": rows,
    }


def build_harness_provenance(model, provider=None, temperature=None, max_steps=None,
                             max_tokens=None, system_prompt=None, config=None,
                             reasoning_effort=None):
    """Create non-secret provenance for a live harness execution."""

    metadata = {
        "run_id": uuid.uuid4().hex,
        "tool_version": TOOL_VERSION,
        "target_model": model,
    }
    if provider:
        metadata["target_provider"] = provider
    if temperature is not None:
        metadata["target_temperature"] = temperature
    if max_steps is not None:
        metadata["max_steps"] = max_steps
    if max_tokens is not None:
        metadata["target_max_tokens"] = max_tokens
    if reasoning_effort is not None:
        metadata["target_reasoning_effort"] = reasoning_effort
    if system_prompt is not None:
        metadata["system_prompt_sha256"] = hashlib.sha256(
            str(system_prompt).encode("utf-8")
        ).hexdigest()
    if isinstance(config, Mapping):
        safe_config = {
            key: config[key]
            for key in (
                "provider", "model", "api_key_env", "base_url",
                "timeout_seconds", "max_tokens", "temperature", "strength_rank",
                "reasoning_effort",
            )
            if key in config
        }
        metadata["target_config_sha256"] = _digest(safe_config)
    return metadata


def build_harness_report(results, mode, generated_at=None, metadata=None):
    """Build a versioned, machine-readable report for harness executions."""

    serialized = []
    for result in results:
        if hasattr(result, "to_dict"):
            result = result.to_dict()
        if not isinstance(result, Mapping):
            raise ValueError("harness results must be mappings or expose to_dict()")
        try:
            json.dumps(result, ensure_ascii=False, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"harness result is not JSON-serializable: {exc}") from exc
        # The report stamps event_schema_version, so every trace it carries
        # must conform, including results supplied as plain mappings.
        if "events" in result:
            try:
                validate_events(result["events"])
            except ValueError as exc:
                raise ValueError(f"harness result has an invalid event trace: {exc}") from exc
        serialized.append(dict(result))

    attack_results = [row for row in serialized if row.get("scenario_kind") == "attack"]
    control_results = [row for row in serialized if row.get("scenario_kind") == "control"]
    operational_errors = sum(
        len(row.get("operational_errors") or []) for row in serialized
    )
    run = dict(metadata or {})
    run.setdefault("run_id", uuid.uuid4().hex)
    run.setdefault("tool_version", TOOL_VERSION)
    return {
        "schema_version": HARNESS_SCHEMA_VERSION,
        "event_schema_version": EVENT_SCHEMA_VERSION,
        "artifact_type": "agentprobe_harness",
        "tool": "agentprobe",
        "tool_version": TOOL_VERSION,
        "generated_at": generated_at or _utc_now(),
        "mode": mode,
        "run": run,
        "summary": {
            "scenarios": len(serialized),
            "attacks": len(attack_results),
            "attack_successes": sum(bool(row.get("attack_succeeded")) for row in attack_results),
            "controls": len(control_results),
            "controls_passed": sum(bool(row.get("control_succeeded")) for row in control_results),
            "operational_errors": operational_errors,
        },
        "results": serialized,
    }


def _write_json_atomic(path, payload, prefix):
    """Atomically write a private JSON artifact to an explicit path."""

    path = os.fspath(path)
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=prefix, suffix=".json", dir=directory)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False, allow_nan=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
        try:
            directory_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return path


def save_json_report(report: Mapping[str, Any], target_model: str, report_dir: str) -> str:
    """Write a scan artifact and return its path."""

    os.makedirs(report_dir, exist_ok=True)
    safe_name = safe_filename_component(target_model)
    run_stamp = _datetime.datetime.now(_datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = str((report.get("run") or {}).get("run_id", uuid.uuid4().hex))
    run_fragment = safe_filename_component(run_id)[:32] or "run"
    path = os.path.join(report_dir, f"scan_{safe_name}_{run_stamp}_{run_fragment[:8]}.json")
    return _write_json_atomic(path, report, ".agentprobe-")


def save_harness_report(report: Mapping[str, Any], path: str) -> str:
    """Atomically write a private harness report to the requested path."""

    if not isinstance(path, str) or not path.strip() or path == "-":
        raise ValueError("harness report path must be a non-empty file path")
    return _write_json_atomic(path, report, ".agentprobe-harness-")
