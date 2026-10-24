"""Production scan orchestration for the AgentProbe package.

The historical v1.1 runner (``agentprobe.legacy.v11``) remains available for
backwards compatibility, but the installable CLI uses this module.  Keeping provider
construction, attack selection, retries, checkpointing, and report emission
inside the package gives automation one supported execution path.
"""

from __future__ import annotations

import os
import time
from typing import Any, Mapping, Optional, Sequence

from agentprobe.attackpack import build_attack_pack
from agentprobe.checkpoints import ScanCheckpoint
from agentprobe.config import client_config, load_config
from agentprobe.detection import (
    JUDGE_PROMPT_SHA256,
    JUDGE_PROMPT_VERSION,
    calculate_finding_severity,
    keyword_check,
    llm_judge,
    sanitize_error,
)
from agentprobe.models import validate_judge_strength
from agentprobe.providers import build_client, preflight_model
from agentprobe.reliability import is_retryable_error
from agentprobe.replay import RecordingClient, ReplayRecording
from agentprobe.packs import AttackPack, load_packs
from agentprobe.signing import trust_policy
from agentprobe.verdicts import VERDICT_RULE, apply_oracle
from agentprobe.reporting import (
    build_json_report, build_run_metadata, save_json_report, scan_attack_id,
)
from agentprobe.termstyle import TAG_WIDTH, style, verdict_tag
from agentprobe.html_report import generate_html_report, save_html_report


SEVERITY_LADDER = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
ERROR_METHODS = frozenset({"target-error", "judge-error"})


def _selection_entry(pack: AttackPack, attack: Mapping[str, Any]) -> dict[str, Any]:
    entry = {field: attack[field] for field in ("prompt", "severity", "description")}
    entry["_library_index"] = attack["index"]
    entry["_oracle"] = attack.get("oracle")
    if not pack.builtin:
        # Part of the digest: the same prompt from a different pack is different evidence.
        entry["_attack_id"] = f"{pack.id}:{attack['id']}"
    return entry


def filter_attacks(config: Mapping[str, Any],
                   packs: Optional[Sequence[AttackPack]] = None) -> dict[str, list[dict[str, Any]]]:
    """Apply the validated category and severity filters to the loaded attack packs.

    ``packs`` defaults to the config's ``packs`` list (or the built-in pack),
    with relative paths read from the working directory. With only the
    built-in pack the selection is exactly the historical library selection.
    """

    if packs is None:
        packs = load_packs(config.get("packs"))
    scan = config.get("scan", {})
    categories_setting = scan.get("categories", "all")
    severity_filter = scan.get("severity_filter")
    available = list(dict.fromkeys(c for pack in packs for c in pack.categories))
    if categories_setting == "all":
        active = available
    else:
        missing = [c for c in categories_setting if c not in available]
        if missing:
            raise ValueError(f"scan.categories names {', '.join(missing)}, which no loaded "
                             "attack pack provides")
        active = list(categories_setting)
    filtered: dict[str, list[dict[str, Any]]] = {}
    for category in active:
        attacks = [_selection_entry(pack, attack)
                   for pack in packs for attack in pack.attacks_in(category)]
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
    judge_reasoning_effort: Optional[str] = None,
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
        reasoning_effort=judge_reasoning_effort,
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
    reasoning_effort: Optional[str] = None,
    system_prompt: Optional[str] = None,
) -> str:
    """Call a target model and turn exhausted failures into explicit evidence."""

    last_error = None
    for attempt in range(retries + 1):
        try:
            request = {
                "messages": ([{"role": "system", "content": system_prompt}]
                             if system_prompt else [])
                            + [{"role": "user", "content": prompt}],
                "model": model,
                "max_tokens": max_tokens,
                "temperature": temperature,
            }
            if reasoning_effort is not None:
                request["reasoning_effort"] = reasoning_effort
            result = client.chat.completions.create(**request)
            choices = getattr(result, "choices", None)
            if not choices:
                raise ValueError("provider response contained no choices")
            content = getattr(getattr(choices[0], "message", None), "content", None)
            if not isinstance(content, str) or not content.strip():
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


_VERDICT_ORDER = ("VULNERABLE", "PARTIAL", "SUSPICIOUS", "SAFE")


def _ascii_preview(prompt: str, width: int = 50) -> str:
    """Prompt preview for the progress line; attack text may contain non-ASCII."""
    return prompt[:width].encode("ascii", "replace").decode("ascii")


def _result_line(verdict: str, finding: Any, method: str) -> str:
    """One verbose line per scored attack, e.g. ``[VULNERABLE]    HIGH finding via llm-judge``."""
    tag = style(verdict_tag(verdict, method))
    if method in ERROR_METHODS:
        return f"  {tag}  no verdict ({method})"
    finding_text = f"{finding} finding " if finding else ""
    return f"  {tag}  {finding_text}via {method}"


def _category_tally(rows: Sequence[Sequence[Any]]) -> str:
    """Per-category count line; errors are counted separately, never as verdicts."""
    errors = sum(1 for row in rows if row[5] in ERROR_METHODS)
    counts = {name: 0 for name in _VERDICT_ORDER}
    for row in rows:
        if row[5] not in ERROR_METHODS and row[2] in counts:
            counts[row[2]] += 1
    parts = [f"{name} {count}" for name, count in counts.items() if count]
    parts.append(f"errors {errors}")
    return "  category total: " + ", ".join(parts)


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
    target_reasoning_effort: Optional[str] = None,
    judge_reasoning_effort: Optional[str] = None,
    target_system_prompt: Optional[str] = None,
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
    providers_preflighted = False
    for category, attacks in attack_library.items():
        if verbose:
            print(f"\n[{category.upper()}] {len(attacks)} prompts")
        category_results = []
        for position, attack in enumerate(attacks, start=1):
            attack_key = scan_attack_id(category, attack, position)
            if checkpoint is not None and checkpoint.has(attack_key):
                row = checkpoint.row(attack_key)
                if not (repair_errors and row[5] in ERROR_METHODS):
                    category_results.append(row)
                    if verbose:
                        print(f"  {style(verdict_tag(row[2], row[5]))}  [resume] "
                              f"{attack_key} via {row[5]}")
                    continue
                checkpoint.remove(attack_key)
                if verbose:
                    print(f"  {'':{TAG_WIDTH}}  [repair] {attack_key} retrying {row[5]}")
                if row[5] == "judge-error" and not is_error_response(row[1]):
                    if not providers_preflighted:
                        preflight_model(target_client, target_model)
                        preflight_model(judge_client, judge_model)
                        providers_preflighted = True
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
                        judge_reasoning_effort=judge_reasoning_effort,
                    )
                    finding = None if method == "judge-error" else calculate_finding_severity(
                        attack["severity"], verdict
                    )
                    marked, verdict, finding, reason, method = apply_oracle(
                        attack, response, verdict, finding, reason, method)
                    repaired = (marked, response, verdict, finding, reason, method)
                    category_results.append(repaired)
                    checkpoint.record(category, repaired, position)
                    if verbose:
                        print(_result_line(verdict, finding, method))
                    continue

            if verbose:
                print(f"  {position}/{len(attacks)} [{attack['severity']}] "
                      f"{_ascii_preview(attack['prompt'])}...")
            if not providers_preflighted:
                preflight_model(target_client, target_model)
                preflight_model(judge_client, judge_model)
                providers_preflighted = True
            response = send_prompt(
                target_client,
                target_model,
                attack["prompt"],
                max_tokens=max_tokens,
                temperature=target_temperature,
                retries=retries,
                delay=retry_delay,
                reasoning_effort=target_reasoning_effort,
                system_prompt=target_system_prompt,
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
                    judge_reasoning_effort=judge_reasoning_effort,
                )
                finding = None if method == "judge-error" else calculate_finding_severity(
                    attack["severity"], verdict
                )
            marked, verdict, finding, reason, method = apply_oracle(
                attack, response, verdict, finding, reason, method)
            row = (marked, response, verdict, finding, reason, method)
            category_results.append(row)
            if checkpoint is not None:
                checkpoint.record(category, row, position)
            if verbose:
                print(_result_line(verdict, finding, method))
            time.sleep(rate_limit)
        scan_results[category] = category_results
        if verbose:
            print(_category_tally(category_results))
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
    verbose: bool = False,
    packs: Sequence[str] = (),
) -> dict[str, Any]:
    """Run the validated, non-interactive scanner and persist configured reports.

    The config's ``packs`` list (relative paths next to the config file, default
    the built-in pack) is extended by ``packs`` (relative to the working directory).
    """

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
    trust = trust_policy(config.get("packs_trust"))
    loaded = load_packs(config.get("packs"), os.path.dirname(os.path.abspath(config_path)),
                        packs, trust=trust)
    # With trusted keys configured, an external pack that is not verified is worth
    # a visible line; without keys, provenance alone records the signature status.
    pack_warnings = [
        f"attack pack {pack.id} {pack.version} is "
        + (f"signed by untrusted key {pack.signer_key_id}" if pack.signed else "not signed")
        + f" (packs_trust mode {trust.mode})"
        for pack in loaded
        if trust.keys and not pack.builtin and not pack.verified
    ]
    attack_library = filter_attacks(config, loaded)
    if not attack_library:
        raise ValueError("No attacks matched the configured scan filters")
    # Each pack covers its full content; attack_library_sha256 records the
    # filtered selection that this scan actually sends.
    attack_pack = build_attack_pack() if any(pack.builtin for pack in loaded) else None

    metadata = build_run_metadata(
        target["model"],
        judge["model"],
        target_provider=target.get("provider"),
        judge_provider=judge.get("provider"),
        config=config,
        attack_library=attack_library,
        judge_prompt_version=JUDGE_PROMPT_VERSION,
        judge_prompt_sha256=JUDGE_PROMPT_SHA256,
        attack_pack=attack_pack,
        attack_packs=[pack.provenance() for pack in loaded],
        verdict_rule=VERDICT_RULE,
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
    target_client = build_client(client_config(target, config_path))
    judge_client = build_client(client_config(judge, config_path))
    if scan.get("record_replay_path"):
        # One shared file: target and judge requests differ by model, so
        # their entries never collide.
        recording = ReplayRecording(scan["record_replay_path"])
        target_client = RecordingClient(target_client, recording)
        judge_client = RecordingClient(judge_client, recording)
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
        target_reasoning_effort=target.get("reasoning_effort"),
        judge_reasoning_effort=judge.get("reasoning_effort"),
        target_system_prompt=target.get("system_prompt"),
        checkpoint=checkpoint,
        resume=resume,
        repair_errors=repair_errors,
        verbose=verbose,
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
    return {"results": results, "html_path": html_path, "json_path": json_path, "report": report,
            "pack_warnings": pack_warnings}
