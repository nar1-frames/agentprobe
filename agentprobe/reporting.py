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


SCHEMA_VERSION = "1.0"
TOOL_VERSION = "1.3.0"
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
                       judge_prompt_sha256=None):
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
            for key in ("temperature", "max_tokens"):
                if key in block:
                    metadata[f"{prefix}_{key}"] = block[key]
        scan = config.get("scan") if isinstance(config, Mapping) else None
        if isinstance(scan, Mapping):
            for key in ("retries", "retry_delay_seconds", "rate_limit_seconds"):
                if key in scan:
                    metadata[f"scan_{key}"] = scan[key]
    if attack_library is not None:
        metadata["attack_library_sha256"] = attack_library_digest(attack_library)
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


def save_json_report(report: Mapping[str, Any], target_model: str, report_dir: str) -> str:
    """Write a scan artifact and return its path."""

    os.makedirs(report_dir, exist_ok=True)
    safe_name = safe_filename_component(target_model)
    run_stamp = _datetime.datetime.now(_datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = str((report.get("run") or {}).get("run_id", uuid.uuid4().hex))
    run_fragment = safe_filename_component(run_id)[:32] or "run"
    path = os.path.join(report_dir, f"scan_{safe_name}_{run_stamp}_{run_fragment[:8]}.json")
    fd, temp_path = tempfile.mkstemp(prefix=".agentprobe-", suffix=".json", dir=report_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, path)
    except Exception:
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass
        raise
    return path
