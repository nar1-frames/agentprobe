"""Production scan orchestration for the AgentProbe package.

The historical ``agentprobe_v11.py`` script remains available for backwards
compatibility, but the installable CLI uses this module.  Keeping provider
construction, attack selection, retries, checkpointing, and report emission
inside the package gives automation one supported execution path.
"""

from __future__ import annotations

import time
from typing import Any, Mapping, Optional, Sequence

from attacks.library import ATTACK_LIBRARY
from agentprobe.checkpoints import ScanCheckpoint
from agentprobe.config import load_config
from agentprobe.detection import (
    JUDGE_PROMPT_SHA256,
    JUDGE_PROMPT_VERSION,
    calculate_finding_severity,
    keyword_check,
    llm_judge,
    sanitize_error,
)
from agentprobe.models import validate_judge_strength
from agentprobe.providers import build_client
from agentprobe.reliability import is_retryable_error
from agentprobe.reporting import build_json_report, build_run_metadata, save_json_report
from report_html_v11 import generate_html_report, save_html_report


SEVERITY_LADDER = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
ERROR_METHODS = frozenset({"target-error", "judge-error"})


def filter_attacks(config: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Apply the validated category and severity filters to the attack library."""

    scan = config.get("scan", {})
    categories_setting = scan.get("categories", "all")
    severity_filter = scan.get("severity_filter")
    active = list(ATTACK_LIBRARY) if categories_setting == "all" else categories_setting
    filtered: dict[str, list[dict[str, Any]]] = {}
    for category in active:
        if category not in ATTACK_LIBRARY:
            continue
        attacks = [
            {**attack, "_library_index": index}
            for index, attack in enumerate(ATTACK_LIBRARY[category], start=1)
        ]
        if severity_filter:
            minimum = SEVERITY_LADDER.index(severity_filter)
            attacks = [
                attack for attack in attacks
                if SEVERITY_LADDER.index(attack["severity"]) >= minimum
            ]
        if attacks:
            filtered[category] = attacks
    return filtered


def assess_vulnerability(
    target_client: Any,
    target_model: str,
    judge_client: Any,
    judge_model: str,
    attack_prompt: str,
    response: str,
    *,
    judge_retries: int = 3,
    judge_retry_delay: float = 5,
    judge_temperature: float = 0.1,
    judge_max_tokens: int = 120,
) -> tuple[str, str, str]:
    """Route one response through the canonical keyword/judge detector."""

    del target_client, target_model
    keyword = keyword_check(response)
    if keyword.decisive:
        return keyword.verdict, keyword.reason, "keyword"
    judge = llm_judge(
        judge_client,
        judge_model,
        attack_prompt,
        response,
        temperature=judge_temperature,
        max_tokens=judge_max_tokens,
        retries=judge_retries,
        delay=judge_retry_delay,
    )
    return judge.verdict, judge.reason, "judge-error" if judge.error else "llm-judge"


def send_prompt(
    client: Any,
    model: str,
    prompt: str,
    *,
    max_tokens: int = 512,
    temperature: float = 0.0,
    retries: int = 2,
    delay: float = 3,
) -> str:
    """Call a target model and turn exhausted failures into explicit evidence."""

    last_error = None
    for attempt in range(retries + 1):
        try:
            result = client.chat.completions.create(
                messages=[{"role": "user", "content": prompt}],
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
            )
            choices = getattr(result, "choices", None)
            if not choices:
                raise ValueError("provider response contained no choices")
            content = getattr(getattr(choices[0], "message", None), "content", None)
            if not isinstance(content, str):
                raise ValueError("provider response contained no text content")
            return content
        except Exception as exc:  # noqa: BLE001 - provider boundary must be recorded
            last_error = sanitize_error(exc)
            if attempt < retries and is_retryable_error(exc):
                time.sleep(delay)
                continue
            break
    return f"[ERROR: request failed after {retries + 1} attempts: {last_error}]"


def is_error_response(response: Any) -> bool:
    """Return whether a target response is an operational failure marker."""

    return isinstance(response, str) and response.startswith("[ERROR:")


def run_full_scan(
    target_client: Any,
    target_model: str,
    judge_client: Any,
    judge_model: str,
    attack_library: Mapping[str, Sequence[Mapping[str, Any]]],
    rate_limit: float,
    *,
    max_tokens: int = 512,
    retries: int = 2,
    retry_delay: float = 3,
    target_temperature: float = 0.0,
    judge_temperature: float = 0.1,
    judge_max_tokens: int = 120,
    checkpoint_path: Optional[str] = None,
    resume: bool = False,
    run_metadata: Optional[Mapping[str, Any]] = None,
    checkpoint: Optional[ScanCheckpoint] = None,
    repair_errors: bool = False,
    verbose: bool = False,
) -> dict[str, list[tuple[Any, ...]]]:
    """Run a scan, optionally checkpointing every completed attack."""

    if checkpoint is not None and checkpoint_path is not None:
        raise ValueError("pass either checkpoint or checkpoint_path, not both")
    if resume and not checkpoint_path and checkpoint is None:
        raise ValueError("resume requires checkpoint_path")
    if repair_errors and not resume:
        raise ValueError("repair_errors requires resume")
    if checkpoint is None and checkpoint_path:
        checkpoint = ScanCheckpoint(
            checkpoint_path,
            target_model=target_model,
            judge_model=judge_model,
            attack_library=attack_library,
            run_metadata=run_metadata,
            resume=resume,
        )

    if verbose:
        total = sum(len(attacks) for attacks in attack_library.values())
        print(f"Target:   {target_model}")
        print(f"Judge:    {judge_model}")
        print(f"Prompts:  {total} across {len(attack_library)} categories")
        print("=" * 60)

    scan_results: dict[str, list[tuple[Any, ...]]] = {}
    for category, attacks in attack_library.items():
        if verbose:
            print(f"\n[{category.upper()}] — {len(attacks)} prompts")
        category_results = []
        for position, attack in enumerate(attacks, start=1):
            attack_key = f"{category}:{attack.get('_library_index', position)}"
            if checkpoint is not None and checkpoint.has(attack_key):
                row = checkpoint.row(attack_key)
                if not (repair_errors and row[5] in ERROR_METHODS):
                    category_results.append(row)
                    if verbose:
                        print(f"  [resume] {attack_key} {row[2]} via {row[5]}")
                    continue
                checkpoint.remove(attack_key)
                if verbose:
                    print(f"  [repair] {attack_key} retrying {row[5]}")
                if row[5] == "judge-error" and not is_error_response(row[1]):
                    response = row[1]
                    verdict, reason, method = assess_vulnerability(
                        target_client,
                        target_model,
                        judge_client,
                        judge_model,
                        attack["prompt"],
                        response,
                        judge_retries=retries,
                        judge_retry_delay=retry_delay,
                        judge_temperature=judge_temperature,
                        judge_max_tokens=judge_max_tokens,
                    )
                    finding = None if method == "judge-error" else calculate_finding_severity(
                        attack["severity"], verdict
                    )
                    repaired = (attack, response, verdict, finding, reason, method)
                    category_results.append(repaired)
                    checkpoint.record(category, repaired, position)
                    if verbose:
                        marker = {"VULNERABLE": "[VULN]", "PARTIAL": "[PART]",
                                  "SUSPICIOUS": "[?]", "SAFE": "[safe]"}.get(verdict, "[?]")
                        print(f"  {marker} {verdict} via {method}")
                    continue

            if verbose:
                print(f"  {position}/{len(attacks)} [{attack['severity']}] "
                      f"{attack['prompt'][:50]}...")
            response = send_prompt(
                target_client,
                target_model,
                attack["prompt"],
                max_tokens=max_tokens,
                temperature=target_temperature,
                retries=retries,
                delay=retry_delay,
            )
            if is_error_response(response):
                verdict, reason, method, finding = "SUSPICIOUS", response, "target-error", None
            else:
                verdict, reason, method = assess_vulnerability(
                    target_client,
                    target_model,
                    judge_client,
                    judge_model,
                    attack["prompt"],
                    response,
                    judge_retries=retries,
                    judge_retry_delay=retry_delay,
                    judge_temperature=judge_temperature,
                    judge_max_tokens=judge_max_tokens,
                )
                finding = None if method == "judge-error" else calculate_finding_severity(
                    attack["severity"], verdict
                )
            row = (attack, response, verdict, finding, reason, method)
            category_results.append(row)
            if checkpoint is not None:
                checkpoint.record(category, row, position)
            if verbose:
                marker = {"VULNERABLE": "[VULN]", "PARTIAL": "[PART]",
                          "SUSPICIOUS": "[?]", "SAFE": "[safe]"}.get(verdict, "[?]")
                finding_text = f"[{finding}]" if finding else ""
                print(f"  {marker} {verdict} {finding_text} via {method}")
            time.sleep(rate_limit)
        scan_results[category] = category_results
        time.sleep(rate_limit)

    if checkpoint is not None:
        checkpoint.finalize()
    return scan_results


def run_configured_scan(
    config_path: str = "config.yaml",
    *,
    checkpoint_path: Optional[str] = None,
    resume: bool = False,
    repair_errors: bool = False,
) -> dict[str, Any]:
    """Run the validated, non-interactive scanner and persist configured reports."""

    if resume and not checkpoint_path:
        raise ValueError("resume requires checkpoint_path")
    if repair_errors and not resume:
        raise ValueError("repair_errors requires resume")

    config = load_config(config_path)
    target = config["target"]
    judge = config["judge"]
    scan = config.get("scan", {})
    output = config.get("output", {})
    validate_judge_strength(target["model"], judge["model"], target, judge)
    attack_library = filter_attacks(config)
    if not attack_library:
        raise ValueError("No attacks matched the configured scan filters")

    metadata = build_run_metadata(
        target["model"],
        judge["model"],
        target_provider=target.get("provider"),
        judge_provider=judge.get("provider"),
        config=config,
        attack_library=attack_library,
        judge_prompt_version=JUDGE_PROMPT_VERSION,
        judge_prompt_sha256=JUDGE_PROMPT_SHA256,
    )
    checkpoint = None
    if checkpoint_path:
        checkpoint = ScanCheckpoint(
            checkpoint_path,
            target_model=target["model"],
            judge_model=judge["model"],
            attack_library=attack_library,
            run_metadata=metadata,
            resume=resume,
        )
        if resume:
            metadata = dict(checkpoint.run_metadata)

    # The checkpoint is validated before provider clients are constructed.
    target_client = build_client(target)
    judge_client = build_client(judge)
    results = run_full_scan(
        target_client,
        target["model"],
        judge_client,
        judge["model"],
        attack_library,
        scan.get("rate_limit_seconds", 1),
        max_tokens=target.get("max_tokens", 512),
        retries=scan.get("retries", 2),
        retry_delay=scan.get("retry_delay_seconds", 3),
        target_temperature=target.get("temperature", 0.0),
        judge_temperature=judge.get("temperature", 0.1),
        judge_max_tokens=judge.get("max_tokens", 120),
        checkpoint=checkpoint,
        resume=resume,
        repair_errors=repair_errors,
    )
    report = build_json_report(results, target["model"], judge["model"], metadata=metadata)
    report_dir = output.get("report_dir", "reports")
    report_format = output.get("report_format", "both")
    html_path = None
    json_path = None
    if report_format in {"html", "both"}:
        html_path = save_html_report(
            generate_html_report(
                results, target["model"], judge["model"], metadata=metadata
            ),
            target["model"],
            report_dir,
            run_id=report["run"]["run_id"],
        )
    if report_format in {"json", "both"}:
        json_path = save_json_report(report, target["model"], report_dir)
    return {"results": results, "html_path": html_path, "json_path": json_path}
