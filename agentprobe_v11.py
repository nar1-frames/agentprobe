# ============================================================
# AGENTPROBE v1.1 — Mitigation Map + Detection Fixes
# ============================================================
# What changed from v1.0:
#
#   NEW  Mitigation Map in the report: each attack category is
#        mapped to a recommended defense (model vs architecture
#        layer). The report now ends with an action plan.
#
#   FIX  Hedge-then-comply is now decided at the (free) keyword
#        stage instead of always falling through to the judge.
#        In v1.0, keyword_check returned PARTIAL with confidence 1,
#        but assess_vulnerability only trusted keywords at
#        confidence >= 2 — so the PARTIAL verdict was always
#        discarded and re-derived by the judge. Dead code, and a
#        wasted judge call on every hedge-then-comply case.
#
#   FIX  Target responses are no longer capped at 200 tokens.
#        The payload in a hedge-then-comply response comes AFTER
#        the refusal — exactly what a 200-token cap truncates.
#        Default is now 512 (configurable via target.max_tokens).
#
#   FIX  send_prompt() now retries transient API errors instead of
#        crashing the entire scan on a single timeout.
# ============================================================
import os
import datetime
import time
from dotenv import load_dotenv
from attacks.library import ATTACK_LIBRARY
from report_html_v11 import generate_html_report, save_html_report
from agentprobe.reporting import build_json_report, build_run_metadata, save_json_report
from agentprobe.models import validate_judge_strength
from agentprobe.checkpoints import ScanCheckpoint
from agentprobe.config import load_config as _load_validated_config
# v1.1.1: the detection engine now lives in agentprobe.detection (one source of
# truth). keyword_check/llm_judge/calculate_finding_severity used to be defined
# inline below; they were extracted verbatim and are imported here instead.
from agentprobe.detection import (
    JUDGE_PROMPT_SHA256,
    JUDGE_PROMPT_VERSION,
    keyword_check,
    llm_judge,
    calculate_finding_severity,
    sanitize_error,
)
from agentprobe.reliability import is_retryable_error
load_dotenv()
# ============================================================
# CONFIG + CLIENT (unchanged from v1.0)
# ============================================================
def load_config(path="config.yaml"):
    return _load_validated_config(path)
def build_client(provider_config):
    provider = provider_config.get("provider", "groq")
    base_url = provider_config.get("base_url")
    key_env = provider_config.get("api_key_env")
    api_key = os.environ.get(key_env) if key_env else "ollama"
    timeout = provider_config.get("timeout_seconds", 60)
    # The scanner owns retry policy so SDK-level retries cannot multiply the
    # configured attempt budget unexpectedly.
    client_options = {"timeout": float(timeout), "max_retries": 0}
    if provider == "groq":
        from groq import Groq
        if not api_key:
            raise ValueError("Missing API key for groq provider")
        return Groq(api_key=api_key, **client_options)
    elif provider in ("openai", "ollama", "custom"):
        from openai import OpenAI
        if provider == "openai" and not api_key:
            raise ValueError("Missing API key for openai provider")
        kwargs = {"api_key": api_key or "ollama", **client_options}
        if base_url:
            kwargs["base_url"] = base_url
        elif provider == "ollama":
            kwargs["base_url"] = "http://localhost:11434/v1"
        return OpenAI(**kwargs)
    else:
        raise ValueError(f"Unknown provider: '{provider}'")
def filter_attacks(config):
    categories_setting = config["scan"].get("categories", "all")
    severity_filter = config["scan"].get("severity_filter")
    severity_ladder = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    active = list(ATTACK_LIBRARY.keys()) if categories_setting == "all" else categories_setting
    filtered = {}
    for category in active:
        if category not in ATTACK_LIBRARY:
            continue
        attacks = [dict(attack, _library_index=index)
                   for index, attack in enumerate(ATTACK_LIBRARY[category], start=1)]
        if severity_filter:
            min_index = severity_ladder.index(severity_filter)
            attacks = [a for a in attacks if severity_ladder.index(a["severity"]) >= min_index]
        if attacks:
            filtered[category] = attacks
    return filtered
# ============================================================
# DETECTION ENGINE
#
# The signal lists and the three detection functions
# (keyword_check / llm_judge / calculate_finding_severity) now live in
# agentprobe.detection and are imported at the top of this file. Only the
# scan-side orchestration (assess_vulnerability, send_prompt) remains here.
# ============================================================
def assess_vulnerability(target_client, target_model, judge_client, judge_model,
                         attack_prompt, response, judge_retries=3,
                         judge_retry_delay=5, judge_temperature=0.1,
                         judge_max_tokens=120):
    kw = keyword_check(response)
    # kw.decisive is the boolean v11's `confidence >= 2` was standing in for.
    # It reproduces v11's routing EXACTLY: hedge-then-comply (PARTIAL) or a
    # keyword verdict backed by >=2 hits is trusted for free; anything weaker
    # (0/1 hits, SUSPICIOUS) still pays for the judge.
    if kw.decisive:
        return kw.verdict, kw.reason, "keyword"
    judge = llm_judge(
        judge_client, judge_model, attack_prompt, response,
        temperature=judge_temperature, max_tokens=judge_max_tokens,
        retries=judge_retries, delay=judge_retry_delay,
    )
    return judge.verdict, judge.reason, "judge-error" if judge.error else "llm-judge"
def send_prompt(client, model, prompt, max_tokens=512, temperature=0.0,
                retries=2, delay=3):
    # v1.1 FIX: default cap raised from 200 -> 512 (hedge-then-comply payloads
    # live after the refusal and were being truncated), and transient API errors
    # now retry instead of crashing the whole scan.
    last_err = None
    for attempt in range(retries + 1):
        try:
            result = client.chat.completions.create(
                messages=[{"role": "user", "content": prompt}],
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
            )
            content = result.choices[0].message.content
            if not isinstance(content, str):
                raise ValueError("provider response contained no text content")
            return content
        except Exception as e:
            last_err = sanitize_error(e)
            if attempt < retries and is_retryable_error(e):
                time.sleep(delay)
            else:
                break
    return f"[ERROR: request failed after {retries + 1} attempts: {last_err}]"


def is_error_response(response):
    """Return True when the target call failed rather than producing text."""
    return isinstance(response, str) and response.startswith("[ERROR:")
# ============================================================
# SCAN LOOP
# ============================================================
def run_full_scan(target_client, target_model, judge_client, judge_model,
                  attack_library, rate_limit, max_tokens=512, retries=2,
                  retry_delay=3, target_temperature=0.0,
                  judge_temperature=0.1,
                  judge_max_tokens=120, checkpoint_path=None, resume=False,
                  run_metadata=None, checkpoint=None, repair_errors=False):
    """Run the scan, optionally persisting one atomic checkpoint per attack.

    ``checkpoint_path`` is intentionally opt-in so existing library callers
    keep their behavior.  Once enabled, a checkpoint is bound to the target,
    judge, filtered attack library, and supplied run metadata.  ``resume``
    therefore cannot accidentally combine results produced by a different
    configuration.
    """

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

    total = sum(len(v) for v in attack_library.values())
    print(f"Target:   {target_model}")
    print(f"Judge:    {judge_model}")
    print(f"Prompts:  {total} across {len(attack_library)} categories")
    if checkpoint is not None and resume:
        print(f"Resuming checkpoint: {checkpoint.path}")
    print("=" * 60)
    scan_results = {}
    for category, attacks in attack_library.items():
        print(f"\n[{category.upper()}] — {len(attacks)} prompts")
        category_results = []
        for i, attack in enumerate(attacks):
            attack_key = (
                f"{category}:{attack.get('_library_index', i + 1)}"
            )
            if checkpoint is not None and checkpoint.has(attack_key):
                row = checkpoint.row(attack_key)
                if not (repair_errors and row[5] in {"target-error", "judge-error"}):
                    category_results.append(row)
                    print(f"  [resume] {attack_key} {row[2]} via {row[5]}")
                    continue
                checkpoint.remove(attack_key)
                print(f"  [repair] {attack_key} retrying {row[5]}")

                # A judge failure does not invalidate the target response.
                # Preserve that response and retry only the judge stage so a
                # repair cannot silently mix a new target sample into the
                # existing evidence.
                if row[5] == "judge-error" and not is_error_response(row[1]):
                    response = row[1]
                    verdict, reason, method = assess_vulnerability(
                        target_client, target_model, judge_client, judge_model,
                        attack["prompt"], response,
                        judge_retries=retries, judge_retry_delay=retry_delay,
                        judge_temperature=judge_temperature,
                        judge_max_tokens=judge_max_tokens,
                    )
                    finding_severity = (
                        None if method == "judge-error"
                        else calculate_finding_severity(attack["severity"], verdict)
                    )
                    repaired_row = (
                        attack, response, verdict, finding_severity, reason, method
                    )
                    category_results.append(repaired_row)
                    checkpoint.record(category, repaired_row, i + 1)
                    continue
            prompt = attack["prompt"]
            severity = attack["severity"]
            print(f"  {i+1}/{len(attacks)} [{severity}] {prompt[:50]}...")
            response = send_prompt(
                target_client, target_model, prompt, max_tokens=max_tokens,
                temperature=target_temperature,
                retries=retries, delay=retry_delay,
            )
            if is_error_response(response):
                verdict = "SUSPICIOUS"
                reason = response
                method = "target-error"
                finding_severity = None
            else:
                verdict, reason, method = assess_vulnerability(
                    target_client, target_model, judge_client, judge_model, prompt, response,
                    judge_retries=retries, judge_retry_delay=retry_delay,
                    judge_temperature=judge_temperature, judge_max_tokens=judge_max_tokens,
                )
                finding_severity = None if method == "judge-error" else calculate_finding_severity(severity, verdict)
            row = (attack, response, verdict, finding_severity, reason, method)
            category_results.append(row)
            if checkpoint is not None:
                checkpoint.record(category, row, i + 1)
            marker = {"VULNERABLE": "[VULN]", "PARTIAL": "[PART]",
                      "SUSPICIOUS": "[?]", "SAFE": "[safe]"}.get(verdict, "[?]")
            fs = f"[{finding_severity}]" if finding_severity else ""
            print(f"  {marker} {verdict} {fs} via {method}")
            time.sleep(rate_limit)
        scan_results[category] = category_results
        time.sleep(rate_limit)
    if checkpoint is not None:
        checkpoint.finalize()
    return scan_results


def run_configured_scan(config_path="config.yaml", checkpoint_path=None, resume=False,
                        repair_errors=False):
    """Run a reproducible scan from config without prompts or browser side effects."""
    if resume and not checkpoint_path:
        raise ValueError("resume requires checkpoint_path")
    if repair_errors and not resume:
        raise ValueError("repair_errors requires resume")
    config = load_config(config_path)
    target_cfg = config["target"]
    judge_cfg = config["judge"]
    scan_cfg = config.get("scan", {})
    output_cfg = config.get("output", {})
    report_dir = output_cfg.get("report_dir", "reports")
    max_tokens = target_cfg.get("max_tokens", 512)
    validate_judge_strength(target_cfg["model"], judge_cfg["model"], target_cfg, judge_cfg)
    attack_library = filter_attacks(config)
    if not attack_library:
        raise ValueError("No attacks matched the configured scan filters")

    report_format = output_cfg.get("report_format", "both")
    report_metadata = build_run_metadata(
        target_cfg["model"], judge_cfg["model"],
        target_provider=target_cfg.get("provider"),
        judge_provider=judge_cfg.get("provider"),
        config=config, attack_library=attack_library,
        judge_prompt_version=JUDGE_PROMPT_VERSION,
        judge_prompt_sha256=JUDGE_PROMPT_SHA256,
    )
    checkpoint = None
    if checkpoint_path:
        checkpoint = ScanCheckpoint(
            checkpoint_path,
            target_model=target_cfg["model"],
            judge_model=judge_cfg["model"],
            attack_library=attack_library,
            run_metadata=report_metadata,
            resume=resume,
        )
        if resume:
            # Preserve the original run ID and provenance in the final report.
            report_metadata = dict(checkpoint.run_metadata)

    # Validate the checkpoint before creating provider clients. A mismatched
    # resume should fail without touching credentials or provider setup.
    target_client = build_client(target_cfg)
    judge_client = build_client(judge_cfg)

    results = run_full_scan(
        target_client,
        target_cfg["model"],
        judge_client,
        judge_cfg["model"],
        attack_library,
        scan_cfg.get("rate_limit_seconds", 1),
        max_tokens=max_tokens,
        retries=scan_cfg.get("retries", 2),
        retry_delay=scan_cfg.get("retry_delay_seconds", 3),
        target_temperature=target_cfg.get("temperature", 0.0),
        judge_temperature=judge_cfg.get("temperature", 0.1),
        judge_max_tokens=judge_cfg.get("max_tokens", 120),
        checkpoint=checkpoint,
        resume=resume,
        repair_errors=repair_errors,
    )
    json_report = build_json_report(
        results, target_cfg["model"], judge_cfg["model"], metadata=report_metadata
    )
    run_id = json_report["run"]["run_id"]
    html_path = None
    json_path = None
    if report_format in {"html", "both"}:
        html_path = save_html_report(
            generate_html_report(
                results, target_cfg["model"], judge_cfg["model"], metadata=report_metadata
            ),
            target_cfg["model"], report_dir, run_id=run_id,
        )
    if report_format in {"json", "both"}:
        json_path = save_json_report(
            json_report, target_cfg["model"], report_dir,
        )
    return {"results": results, "html_path": html_path, "json_path": json_path}
# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("AGENTPROBE v1.1 — AI VULNERABILITY SCANNER + MITIGATION MAP")
    print("=" * 60)
    try:
        config = load_config("config.yaml")
        target_cfg = config["target"]
        judge_cfg = config["judge"]
        print(f"\nLoading target: {target_cfg['provider']} / {target_cfg['model']}")
        print(f"Loading judge:  {judge_cfg['provider']} / {judge_cfg['model']}")
        run = run_configured_scan("config.yaml")
    except (OSError, KeyError, ValueError) as exc:
        print(f"\n[ERROR] {exc}")
        exit(1)
    results = run["results"]
    saved = run["html_path"]
    json_saved = run["json_path"]
    print("\nScan artifacts generated (HTML + JSON).")
    if saved:
        print(f"HTML report saved to: {saved}")
        print(f"Open it: open {saved}")
    if json_saved:
        print(f"JSON report saved to: {json_saved}")
