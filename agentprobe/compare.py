"""Baseline/regression comparison of two scan JSON reports.

Rows are matched by attack ID ("category:index"), which only identifies the
same attack when both reports were built from the same attack library. The
comparison therefore binds itself to ``attack_library_sha256``: a different or
missing digest makes the reports incomparable, while a changed target, judge,
judge prompt, or attack pack is reported as a warning the reader must see.

The result carries IDs, categories, verdicts, severities, methods, and
statuses only. Prompts, responses, and judge reasons are never copied, so a
comparison can be shared more widely than the reports it summarizes.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional

from agentprobe.reporting import VERDICTS


COMPARISON_SCHEMA_VERSION = "1.0"
VERDICT_RANK = {"SAFE": 0, "SUSPICIOUS": 1, "PARTIAL": 2, "VULNERABLE": 3}
CHANGE_CLASSES = (
    "regressed", "improved", "unchanged", "newly_errored",
    "recovered", "still_errored", "added", "removed",
)
_FINDING_VERDICTS = frozenset({"VULNERABLE", "PARTIAL"})
# (field, blocking). Only a different library or report schema makes rows
# incomparable; the rest are legitimate things to compare but must be visible.
_COMPARABILITY_FIELDS = (
    ("schema_version", True),
    ("attack_library_sha256", True),
    ("judge_prompt_sha256", False),
    ("target_model", False),
    ("judge_model", False),
    ("attack_pack_sha256", False),
)


def validate_scan_report(report: Any, label: str = "report") -> None:
    """Raise ValueError unless ``report`` looks like an AgentProbe scan report."""

    if not isinstance(report, Mapping) or report.get("tool") != "agentprobe":
        raise ValueError(f"{label} is not an AgentProbe report")
    if report.get("artifact_type") == "agentprobe_harness":
        raise ValueError(f"{label} is a harness report; compare supports scan reports only")
    rows = report.get("results")
    if not isinstance(rows, list):
        raise ValueError(f"{label} has no results list")
    seen = set()
    for row in rows:
        if (not isinstance(row, Mapping) or not isinstance(row.get("attack_id"), str)
                or not isinstance(row.get("category"), str)
                or row.get("verdict") not in VERDICTS
                or row.get("status") not in {"complete", "error"}):
            raise ValueError(f"{label} contains a row that is not a scan result")
        if row["attack_id"] in seen:
            raise ValueError(f"{label} contains duplicate attack ID {row['attack_id']}")
        seen.add(row["attack_id"])


def _field(report: Mapping[str, Any], name: str) -> Any:
    if name == "schema_version":
        return report.get("schema_version")
    run = report.get("run") or {}
    if name in {"target_model", "judge_model"}:
        return run.get(name, report.get(name))
    return run.get(name)


def _comparability(baseline: Mapping[str, Any], candidate: Mapping[str, Any]) -> Dict[str, Any]:
    mismatches = []
    for name, blocking in _COMPARABILITY_FIELDS:
        before, after = _field(baseline, name), _field(candidate, name)
        if name == "attack_library_sha256" and (before is None or after is None):
            # Without both digests, matching attack IDs proves nothing.
            mismatches.append({"field": name, "baseline": before, "candidate": after,
                               "blocking": True, "reason": "missing"})
            continue
        if name == "attack_pack_sha256" and (before is None or after is None):
            continue
        if before != after:
            mismatches.append({"field": name, "baseline": before, "candidate": after,
                               "blocking": blocking, "reason": "differs"})
    return {
        "comparable": not any(item["blocking"] for item in mismatches),
        "mismatches": mismatches,
    }


def _state(row: Optional[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
    if row is None:
        return None
    return {key: row.get(key) for key in ("verdict", "finding_severity", "method", "status")}


def _classify(before: Optional[Mapping[str, Any]], after: Optional[Mapping[str, Any]]) -> str:
    if before is None:
        return "added"
    if after is None:
        return "removed"
    before_error, after_error = before["status"] == "error", after["status"] == "error"
    if before_error and after_error:
        return "still_errored"
    if after_error:
        return "newly_errored"
    if before_error:
        return "recovered"
    delta = VERDICT_RANK[after["verdict"]] - VERDICT_RANK[before["verdict"]]
    return "regressed" if delta > 0 else "improved" if delta < 0 else "unchanged"


def _findings(rows: List[Mapping[str, Any]]) -> int:
    return sum(row["status"] == "complete" and row["verdict"] in _FINDING_VERDICTS for row in rows)


def _identity(report: Mapping[str, Any]) -> Dict[str, Any]:
    run = report.get("run") or {}
    return {
        "run_id": run.get("run_id"),
        "generated_at": report.get("generated_at"),
        "target_model": _field(report, "target_model"),
        "judge_model": _field(report, "judge_model"),
    }


def _sort_key(entry: Dict[str, Any], index: Any) -> tuple:
    numeric = index if isinstance(index, int) and not isinstance(index, bool) else float("inf")
    return (entry["category"], numeric, entry["attack_id"])


def compare_scan_reports(baseline: Mapping[str, Any], candidate: Mapping[str, Any]) -> Dict[str, Any]:
    """Classify every attack's change from ``baseline`` to ``candidate``."""

    validate_scan_report(baseline, "baseline")
    validate_scan_report(candidate, "candidate")
    before_rows = {row["attack_id"]: row for row in baseline["results"]}
    after_rows = {row["attack_id"]: row for row in candidate["results"]}

    keyed = []
    for attack_id in set(before_rows) | set(after_rows):
        before, after = before_rows.get(attack_id), after_rows.get(attack_id)
        source = before or after
        entry = {
            "attack_id": attack_id,
            "category": source["category"],
            "baseline": _state(before),
            "candidate": _state(after),
            "change": _classify(before, after),
            # Diagnostic only: a keyword decision that moved to the judge (or
            # back) is worth seeing even when the verdict did not change.
            "method_changed": bool(
                before and after and before["status"] == after["status"] == "complete"
                and before.get("method") != after.get("method")
            ),
        }
        keyed.append((_sort_key(entry, source.get("attack_index")), entry))
    changes = [entry for _, entry in sorted(keyed, key=lambda item: item[0])]

    summary = {name: 0 for name in CHANGE_CLASSES}
    for entry in changes:
        summary[entry["change"]] += 1
    summary["method_changed"] = sum(entry["method_changed"] for entry in changes)
    summary["net_findings_delta"] = _findings(candidate["results"]) - _findings(baseline["results"])
    return {
        "schema_version": COMPARISON_SCHEMA_VERSION,
        "baseline": _identity(baseline),
        "candidate": _identity(candidate),
        "comparability": _comparability(baseline, candidate),
        "summary": summary,
        "changes": changes,
    }


def _describe(state: Optional[Mapping[str, Any]]) -> str:
    if state is None:
        return "absent"
    if state["status"] == "error":
        return str(state["method"])
    return f"{state['verdict']} via {state['method']}"


def format_comparison_text(result: Mapping[str, Any]) -> str:
    """Return a short human summary of a comparison result."""

    comparability = result["comparability"]
    blocking = [m["field"] for m in comparability["mismatches"] if m["blocking"]]
    warnings = [m["field"] for m in comparability["mismatches"] if not m["blocking"]]
    if comparability["comparable"]:
        line = "Comparable: yes"
        if warnings:
            line += f" (changed: {', '.join(warnings)})"
    else:
        line = f"NOT COMPARABLE: {', '.join(blocking)} differ or are missing"
        if warnings:
            line += f"; also changed: {', '.join(warnings)}"
    summary = result["summary"]
    lines = [
        line,
        ", ".join(f"{name}={summary[name]}" for name in CHANGE_CLASSES)
        + f"; method_changed={summary['method_changed']}"
        + f"; net_findings_delta={summary['net_findings_delta']:+d}",
    ]
    for entry in result["changes"]:
        if entry["change"] in {"regressed", "newly_errored", "added", "removed"}:
            lines.append(
                f"  {entry['change'].upper()} {entry['attack_id']}: "
                f"{_describe(entry['baseline'])} -> {_describe(entry['candidate'])}"
            )
    return "\n".join(lines) + "\n"
