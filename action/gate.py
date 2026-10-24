"""Decide whether an AgentProbe run fails the job, from its SARIF log.

The composite action calls this after `agentprobe ... --sarif`. It reads only
the data-minimized SARIF the CLI writes, so it works with any
agentprobe-security 2.x release and needs nothing beyond the standard
library. It writes step outputs and a job summary when GitHub provides the
files, prints one verdict line, and exits 1 when the job should fail.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Mapping, Tuple

# Verdicts from least to most severe; fail-on names the lowest one that fails.
SCAN_VERDICTS = ("SAFE", "SUSPICIOUS", "PARTIAL", "VULNERABLE")
FAIL_ON = {"vulnerable": "VULNERABLE", "partial": "PARTIAL", "suspicious": "SUSPICIOUS",
           "never": None}
COMMANDS = ("scan", "demo", "harness")
_HARNESS_ERRORS = re.compile(r"^operational errors: (\d+)$")


def load_results(path: str) -> List[Mapping[str, Any]]:
    with open(path, encoding="utf-8") as handle:
        log = json.load(handle)
    runs = log.get("runs") if isinstance(log, Mapping) else None
    if not isinstance(runs, list) or not runs or not isinstance(runs[0], Mapping):
        raise ValueError("not a SARIF log with a run")
    results = runs[0].get("results")
    if not isinstance(results, list):
        raise ValueError("SARIF run has no results list")
    return [result for result in results if isinstance(result, Mapping)]


def count_scan(results: List[Mapping[str, Any]]) -> Dict[str, int]:
    counts = {verdict: 0 for verdict in SCAN_VERDICTS}
    counts["operational_errors"] = 0
    for result in results:
        properties = result.get("properties") or {}
        if properties.get("status") == "error" or result.get("kind") == "open":
            counts["operational_errors"] += 1
        elif properties.get("verdict") in SCAN_VERDICTS:
            counts[properties["verdict"]] += 1
    return counts


def count_harness(results: List[Mapping[str, Any]]) -> Dict[str, int]:
    counts = {"attacks_succeeded": 0, "controls_failed": 0, "operational_errors": 0}
    for result in results:
        text = str((result.get("message") or {}).get("text", ""))
        if result.get("kind") == "open":
            match = _HARNESS_ERRORS.match(text)
            counts["operational_errors"] += int(match.group(1)) if match else 1
        elif result.get("kind") == "fail":
            key = "controls_failed" if text == "control failed" else "attacks_succeeded"
            counts[key] += 1
    return counts


def decide(command: str, counts: Mapping[str, int], fail_on: str,
           fail_on_error: bool) -> Tuple[bool, List[str]]:
    """Return (failed, reasons) for one run's counts."""

    reasons = []
    if command == "harness":
        if fail_on != "never":
            if counts["attacks_succeeded"]:
                reasons.append(f"{counts['attacks_succeeded']} attack(s) reached their objective")
            if counts["controls_failed"]:
                reasons.append(f"{counts['controls_failed']} control(s) failed")
    elif FAIL_ON[fail_on] is not None:
        floor = SCAN_VERDICTS.index(FAIL_ON[fail_on])
        hits = [f"{counts[v]} {v}" for v in SCAN_VERDICTS[floor:][::-1] if counts[v]]
        if hits:
            reasons.append(f"{', '.join(hits)} at or above fail-on: {fail_on}")
    if fail_on_error and counts["operational_errors"]:
        reasons.append(f"{counts['operational_errors']} operational error(s) and "
                       "fail-on-error is true")
    return bool(reasons), reasons


def _append(path_variable: str, text: str) -> None:
    path = os.environ.get(path_variable)
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(text)


def _summary(command: str, counts: Mapping[str, int], failed: bool,
             reasons: List[str]) -> str:
    rows = "\n".join(f"| {key.replace('_', ' ')} | {value} |" for key, value in counts.items())
    verdict = "FAIL" if failed else "PASS"
    why = "".join(f"\n- {reason}" for reason in reasons)
    return f"### AgentProbe {command}: {verdict}\n\n| result | count |\n|---|---|\n{rows}\n{why}\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sarif", required=True)
    parser.add_argument("--command", required=True)
    parser.add_argument("--fail-on", default="vulnerable")
    parser.add_argument("--fail-on-error", default="true")
    parser.add_argument("--exit-code", type=int, default=0,
                        help="exit code of the agentprobe run that wrote the SARIF")
    args = parser.parse_args(argv)
    fail_on = args.fail_on.strip().lower()
    if args.command not in COMMANDS or fail_on not in FAIL_ON:
        print(f"agentprobe action: command must be one of {', '.join(COMMANDS)} and fail-on "
              f"one of {', '.join(FAIL_ON)} (got {args.command!r}, {args.fail_on!r})")
        return 2
    fail_on_error = args.fail_on_error.strip().lower() in {"true", "1", "yes"}

    if args.exit_code != 0:
        print(f"AgentProbe: FAIL - agentprobe exited {args.exit_code} "
              "(configuration or input error; see the log above)")
        _append("GITHUB_OUTPUT", "result=fail\n")
        return 1
    try:
        results = load_results(args.sarif)
    except (OSError, ValueError) as exc:
        print(f"AgentProbe: FAIL - cannot read SARIF {args.sarif}: {exc}")
        _append("GITHUB_OUTPUT", "result=fail\n")
        return 1

    counts = count_harness(results) if args.command == "harness" else count_scan(results)
    failed, reasons = decide(args.command, counts, fail_on, fail_on_error)
    outputs = {key.lower().replace("_", "-"): value for key, value in counts.items()}
    outputs["result"] = "fail" if failed else "pass"
    _append("GITHUB_OUTPUT", "".join(f"{key}={value}\n" for key, value in outputs.items()))
    _append("GITHUB_STEP_SUMMARY", _summary(args.command, counts, failed, reasons))
    tally = ", ".join(f"{key} {value}" for key, value in outputs.items() if key != "result")
    print(f"AgentProbe: {'FAIL' if failed else 'PASS'} - {tally}")
    for reason in reasons:
        print(f"  {reason}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
