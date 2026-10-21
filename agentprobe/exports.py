"""Data-minimized SARIF and JUnit exports of scan and harness reports.

CI artifacts travel further than ``reports/``: they are uploaded to code
scanning, attached to build pages, and retained by CI providers. These
converters therefore never copy target responses, judge reasons, error
strings, assistant messages, or tool traces. They carry identifiers,
verdicts, methods, statuses, severities, and public attack-library or
scenario-definition text only.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Mapping, Optional

from agentprobe.reporting import VERDICTS, _write_text_atomic


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
INFORMATION_URI = "https://github.com/nar1-frames/agentprobe"

# verdict -> (SARIF kind, SARIF level). SARIF 2.1.0 §3.27.9 requires level
# "none" whenever kind is not "fail", so SUSPICIOUS is review/none.
SCAN_SARIF_OUTCOMES = {
    "VULNERABLE": ("fail", "error"),
    "PARTIAL": ("fail", "warning"),
    "SUSPICIOUS": ("review", "none"),
    "SAFE": ("pass", "none"),
}
# Only these method names are exported; anything else is reported as
# "unknown" so free text can never travel in the method field.
_METHODS = frozenset({"keyword", "llm-judge", "target-error", "judge-error"})
_XML_INVALID = re.compile("[^\u0009\u000a\u000d -퟿-�\U00010000-\U0010ffff]")


def _method(row: Mapping[str, Any]) -> str:
    method = row.get("method")
    return method if method in _METHODS else "unknown"


def _scan_rows(report: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    rows = report.get("results") if isinstance(report, Mapping) else None
    if not isinstance(rows, list):
        raise ValueError("scan report results must be a list")
    for row in rows:
        if not isinstance(row, Mapping) or row.get("verdict") not in VERDICTS:
            raise ValueError("scan report rows must carry a known verdict")
    return rows


def _harness_rows(report: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    rows = report.get("results") if isinstance(report, Mapping) else None
    if not isinstance(rows, list) or not all(isinstance(row, Mapping) for row in rows):
        raise ValueError("harness report results must be a list of objects")
    return rows


def _present(values: Mapping[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in values.items() if value is not None}


def _logical_location(category: str, attack_id: str) -> Dict[str, Any]:
    return {"logicalLocations": [{
        "name": attack_id, "kind": "attack", "fullyQualifiedName": f"{category}/{attack_id}",
    }]}


def _sarif_log(report: Mapping[str, Any], rules: List[Dict[str, Any]],
               results: List[Dict[str, Any]], properties: Mapping[str, Any],
               operational_errors: int) -> Dict[str, Any]:
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": "agentprobe",
                "version": str(report.get("tool_version") or (report.get("run") or {}).get("tool_version") or "unknown"),
                "informationUri": INFORMATION_URI,
                "rules": rules,
            }},
            "invocations": [{"executionSuccessful": operational_errors == 0}],
            "results": results,
            "properties": _present(properties),
        }],
    }


def _rule(rule_id: str, category: str, text: Optional[str], properties: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "id": rule_id,
        "name": category,
        "shortDescription": {"text": text or rule_id},
        "properties": _present(properties),
    }


def scan_report_to_sarif(report: Mapping[str, Any]) -> Dict[str, Any]:
    """Convert a scan JSON report into a SARIF 2.1.0 log."""

    rows = _scan_rows(report)
    run = report.get("run") or {}
    rules, results, seen = [], [], set()
    for row in rows:
        attack_id, category = str(row.get("attack_id")), str(row.get("category"))
        if attack_id not in seen:
            seen.add(attack_id)
            rules.append(_rule(attack_id, category, row.get("description"), {
                "attack_severity": row.get("attack_severity"), "category": category,
            }))
        method, verdict = _method(row), row["verdict"]
        if row.get("status") == "error":
            kind, level, text = "open", "none", f"operational error: {method}"
        else:
            kind, level = SCAN_SARIF_OUTCOMES[verdict]
            text = f"{verdict} via {method}"
            if verdict == "SUSPICIOUS":
                text += "; needs human review"
            elif row.get("finding_severity"):
                text += f" (finding severity {row['finding_severity']})"
        results.append({
            "ruleId": attack_id,
            "kind": kind,
            "level": level,
            "message": {"text": text},
            "locations": [_logical_location(category, attack_id)],
            "properties": _present({
                "verdict": verdict, "method": method, "status": row.get("status"),
                "attack_severity": row.get("attack_severity"),
                "finding_severity": row.get("finding_severity"),
            }),
        })
    errors = sum(row.get("status") == "error" for row in rows)
    return _sarif_log(report, rules, results, {
        "run_id": run.get("run_id"),
        "target_model": run.get("target_model", report.get("target_model")),
        "judge_model": run.get("judge_model", report.get("judge_model")),
        "attack_library_sha256": run.get("attack_library_sha256"),
        "attack_pack_sha256": run.get("attack_pack_sha256"),
        "report_schema_version": report.get("schema_version"),
    }, errors)


def _harness_outcome(row: Mapping[str, Any]) -> tuple[bool, str]:
    """Return (failed, message) for one harness scenario."""

    if row.get("scenario_kind") == "control":
        if row.get("control_succeeded") is True:
            return False, "control passed"
        return True, "control failed"
    if row.get("attack_succeeded"):
        return True, "attack reached its objective"
    return False, "attack blocked"


def harness_report_to_sarif(report: Mapping[str, Any]) -> Dict[str, Any]:
    """Convert a harness JSON report into a SARIF 2.1.0 log."""

    rows = _harness_rows(report)
    run = report.get("run") or {}
    rules, results, seen = [], [], set()
    total_errors = 0
    for row in rows:
        attack_id, category = str(row.get("attack_id")), str(row.get("category"))
        if attack_id not in seen:
            seen.add(attack_id)
            rules.append(_rule(attack_id, category, row.get("objective"), {
                "category": category, "scenario_kind": row.get("scenario_kind"),
            }))
        failed, text = _harness_outcome(row)
        results.append({
            "ruleId": attack_id,
            "kind": "fail" if failed else "pass",
            "level": "error" if failed else "none",
            "message": {"text": text},
            "locations": [_logical_location(category, attack_id)],
        })
        errors = len(row.get("operational_errors") or [])
        total_errors += errors
        if errors:
            results.append({
                "ruleId": attack_id,
                "kind": "open",
                "level": "none",
                "message": {"text": f"operational errors: {errors}"},
                "locations": [_logical_location(category, attack_id)],
            })
    return _sarif_log(report, rules, results, {
        "mode": report.get("mode"),
        "run_id": run.get("run_id"),
        "schema_version": report.get("schema_version"),
        "event_schema_version": report.get("event_schema_version"),
    }, total_errors)


def _xml(value: Any) -> str:
    return _XML_INVALID.sub("", str(value))


def _properties(parent: ET.Element, values: Mapping[str, Any]) -> None:
    present = _present(values)
    if present:
        block = ET.SubElement(parent, "properties")
        for name, value in present.items():
            ET.SubElement(block, "property", {"name": name, "value": _xml(value)})


def _suite(root: ET.Element, name: str, properties: Mapping[str, Any]) -> ET.Element:
    suite = ET.SubElement(root, "testsuite", {"name": _xml(name)})
    _properties(suite, properties)
    return suite


def _finish_junit(root: ET.Element) -> str:
    totals = dict.fromkeys(("tests", "failures", "errors", "skipped"), 0)
    for suite in root.findall("testsuite"):
        cases = suite.findall("testcase")
        counts = {
            "tests": len(cases),
            "failures": sum(case.find("failure") is not None for case in cases),
            "errors": sum(case.find("error") is not None for case in cases),
            "skipped": sum(case.find("skipped") is not None for case in cases),
        }
        for key, value in counts.items():
            suite.set(key, str(value))
            totals[key] += value
    for key, value in totals.items():
        root.set(key, str(value))
    ET.indent(root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"


def scan_report_to_junit(report: Mapping[str, Any]) -> str:
    """Convert a scan JSON report into JUnit XML, one testsuite per category."""

    rows = _scan_rows(report)
    run = report.get("run") or {}
    properties = {
        "run_id": run.get("run_id"),
        "target_model": run.get("target_model", report.get("target_model")),
        "judge_model": run.get("judge_model", report.get("judge_model")),
        "tool_version": run.get("tool_version"),
    }
    root = ET.Element("testsuites", {"name": "agentprobe-scan"})
    suites: Dict[str, ET.Element] = {}
    for row in rows:
        category = str(row.get("category"))
        if category not in suites:
            suites[category] = _suite(root, category, properties)
        case = ET.SubElement(suites[category], "testcase", {
            "classname": _xml(category), "name": _xml(row.get("attack_id")),
        })
        method, verdict = _method(row), row["verdict"]
        if row.get("status") == "error":
            ET.SubElement(case, "error", {"type": method, "message": "operational error"})
        elif verdict in {"VULNERABLE", "PARTIAL"}:
            finding = row.get("finding_severity") or verdict
            failure = ET.SubElement(case, "failure", {
                "type": verdict, "message": f"{_xml(finding)} via {method}",
            })
            failure.text = _xml(row.get("prompt", ""))
        elif verdict == "SUSPICIOUS":
            ET.SubElement(case, "skipped", {"message": "needs human review"})
    return _finish_junit(root)


def harness_report_to_junit(report: Mapping[str, Any]) -> str:
    """Convert a harness JSON report into JUnit XML, one testsuite per mode."""

    rows = _harness_rows(report)
    run = report.get("run") or {}
    root = ET.Element("testsuites", {"name": "agentprobe-harness"})
    suite = _suite(root, str(report.get("mode")), {
        "run_id": run.get("run_id"),
        "tool_version": report.get("tool_version"),
        "schema_version": report.get("schema_version"),
        "event_schema_version": report.get("event_schema_version"),
    })
    for row in rows:
        case = ET.SubElement(suite, "testcase", {
            "classname": _xml(row.get("category")), "name": _xml(row.get("attack_id")),
        })
        failed, text = _harness_outcome(row)
        errors = len(row.get("operational_errors") or [])
        if failed:
            # A security outcome outranks an operational error on the same case.
            message = f"{text}; {errors} operational error(s)" if errors else text
            kind = "control_failed" if row.get("scenario_kind") == "control" else "attack_succeeded"
            ET.SubElement(case, "failure", {"type": kind, "message": message})
        elif errors:
            ET.SubElement(case, "error", {
                "type": "operational_error", "message": f"{errors} operational error(s)",
            })
    return _finish_junit(root)


def write_text_atomic(path: str, text: str) -> str:
    """Write an export with the project's private, atomic artifact pattern."""

    return _write_text_atomic(path, text, ".agentprobe-export-")
