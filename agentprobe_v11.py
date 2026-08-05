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
import yaml
from dotenv import load_dotenv
from attacks.library import ATTACK_LIBRARY
from report_html_v11 import generate_html_report, save_html_report
# v1.1.1: the detection engine now lives in agentprobe.detection (one source of
# truth). keyword_check/llm_judge/calculate_finding_severity used to be defined
# inline below; they were extracted verbatim and are imported here instead.
from agentprobe.detection import (
    keyword_check,
    llm_judge,
    calculate_finding_severity,
)
load_dotenv()
# ============================================================
# CONFIG + CLIENT (unchanged from v1.0)
# ============================================================
def load_config(path="config.yaml"):
    with open(path, "r") as f:
        return yaml.safe_load(f)
def build_client(provider_config):
    provider = provider_config.get("provider", "groq")
    base_url = provider_config.get("base_url")
    key_env = provider_config.get("api_key_env")
    api_key = os.environ.get(key_env) if key_env else "ollama"
    if provider == "groq":
        from groq import Groq
        return Groq(api_key=api_key)
    elif provider in ("openai", "ollama", "custom"):
        from openai import OpenAI
        kwargs = {"api_key": api_key or "ollama"}
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
        attacks = ATTACK_LIBRARY[category]
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
def assess_vulnerability(target_client, target_model, judge_client, judge_model, attack_prompt, response):
    kw = keyword_check(response)
    # kw.decisive is the boolean v11's `confidence >= 2` was standing in for.
    # It reproduces v11's routing EXACTLY: hedge-then-comply (PARTIAL) or a
    # keyword verdict backed by >=2 hits is trusted for free; anything weaker
    # (0/1 hits, SUSPICIOUS) still pays for the judge.
    if kw.decisive:
        return kw.verdict, kw.reason, "keyword"
    judge = llm_judge(judge_client, judge_model, attack_prompt, response)
    return judge.verdict, judge.reason, "llm-judge"
def send_prompt(client, model, prompt, max_tokens=512, retries=2, delay=3):
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
            )
            return result.choices[0].message.content
        except Exception as e:
            last_err = e
            if attempt < retries:
                time.sleep(delay)
    return f"[ERROR: request failed after {retries + 1} attempts: {last_err}]"
# ============================================================
# SCAN LOOP
# ============================================================
def run_full_scan(target_client, target_model, judge_client, judge_model,
                  attack_library, rate_limit, max_tokens=512):
    total = sum(len(v) for v in attack_library.values())
    print(f"Target:   {target_model}")
    print(f"Judge:    {judge_model}")
    print(f"Prompts:  {total} across {len(attack_library)} categories")
    print("=" * 60)
    scan_results = {}
    for category, attacks in attack_library.items():
        print(f"\n[{category.upper()}] — {len(attacks)} prompts")
        category_results = []
        for i, attack in enumerate(attacks):
            prompt = attack["prompt"]
            severity = attack["severity"]
            print(f"  {i+1}/{len(attacks)} [{severity}] {prompt[:50]}...")
            response = send_prompt(target_client, target_model, prompt, max_tokens=max_tokens)
            verdict, reason, method = assess_vulnerability(
                target_client, target_model, judge_client, judge_model, prompt, response
            )
            finding_severity = calculate_finding_severity(severity, verdict)
            category_results.append((attack, response, verdict, finding_severity, reason, method))
            marker = {"VULNERABLE": "[VULN]", "PARTIAL": "[PART]",
                      "SUSPICIOUS": "[?]", "SAFE": "[safe]"}.get(verdict, "[?]")
            fs = f"[{finding_severity}]" if finding_severity else ""
            print(f"  {marker} {verdict} {fs} via {method}")
            time.sleep(rate_limit)
        scan_results[category] = category_results
        time.sleep(rate_limit)
    return scan_results
# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("AGENTPROBE v1.1 — AI VULNERABILITY SCANNER + MITIGATION MAP")
    print("=" * 60)
    config = load_config("config.yaml")
    target_cfg = config["target"]
    judge_cfg = config["judge"]
    scan_cfg = config["scan"]
    output_cfg = config["output"]
    report_dir = output_cfg.get("report_dir", "reports")
    max_tokens = target_cfg.get("max_tokens", 512)
    print(f"\nLoading target: {target_cfg['provider']} / {target_cfg['model']}")
    target_client = build_client(target_cfg)
    target_model = target_cfg["model"]
    print(f"Loading judge:  {judge_cfg['provider']} / {judge_cfg['model']}")
    judge_client = build_client(judge_cfg)
    judge_model = judge_cfg["model"]
    attack_library = filter_attacks(config)
    if not attack_library:
        print("\n[ERROR] No attacks matched your config filters.")
        exit(1)
    total = sum(len(v) for v in attack_library.values())
    print(f"Attacks loaded: {total} prompts\n")
    results = run_full_scan(
        target_client, target_model,
        judge_client, judge_model,
        attack_library,
        scan_cfg.get("rate_limit_seconds", 1),
        max_tokens=max_tokens,
    )
    print("\nGenerating HTML report (with Mitigation Map)...")
    html = generate_html_report(results, target_model, judge_model)
    saved = save_html_report(html, target_model, report_dir)
    print(f"HTML report saved to: {saved}")
    print(f"Open it: open {saved}")
