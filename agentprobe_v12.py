# ============================================================
# AGENTPROBE v1.2 — Interactive model picker (local + cloud)
# ============================================================
# What's new vs v1.1:
#
#   NEW  Model menu. On startup AgentProbe discovers every model
#        you can actually run — local models via Ollama first,
#        plus cloud models (Groq / OpenAI) if their API keys are
#        set — and lets you pick the TARGET and the JUDGE from a
#        numbered list. No more editing config.yaml by hand, and no
#        more "model does not exist" surprises when a cloud provider
#        retires a model.
#
#   NEW  The one rule, enforced in code: the JUDGE must be at least
#        as smart as the TARGET. AgentProbe reads each model's size
#        (the "3b / 8b / 70b" in its name or metadata) and refuses
#        to let you pick a judge weaker than the target. A judge
#        that shares the target's blind spots can't catch the
#        target's subtle failures — so this isn't a nag, it's the
#        thing that keeps your results honest.
#
#   KEEP The parts you liked: the 🔴 VULNERABLE / 🟢 SAFE console
#        verdicts, the severity labels, the Mitigation Map, and the
#        self-contained HTML report — all still here, and the report
#        auto-opens when the scan finishes.
#
# Everything below reuses the v1.1 engine (attacks, detection,
# report) so there is one source of truth for how a response is
# judged. This file only adds the picker + the judge-strength rule.
# ============================================================

import os
import sys
import json
import time
import urllib.request
import webbrowser

# Reuse the package scanner and report — one supported execution path.
from agentprobe.scanner import (
    build_client, filter_attacks, load_config,
    send_prompt, is_error_response, assess_vulnerability, calculate_finding_severity,
    run_full_scan,
)
from report_html_v11 import generate_html_report, save_html_report
from agentprobe.reporting import build_json_report, build_run_metadata, save_json_report
from agentprobe.models import parse_model_size_b
from agentprobe.detection import JUDGE_PROMPT_SHA256, JUDGE_PROMPT_VERSION

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")

# Console verdict styling — the part you liked.
VERDICT_EMOJI = {
    "VULNERABLE": "🔴", "PARTIAL": "🟠",
    "SUSPICIOUS": "🟡", "SAFE": "🟢",
}


# ============================================================
# MODEL SIZE — how we enforce "judge >= target"
# ============================================================

def parse_size_b(text):
    """Backwards-compatible picker alias for the canonical model parser."""
    return parse_model_size_b(text)


# ============================================================
# MODEL DISCOVERY
# ============================================================

def discover_ollama():
    """List locally-installed Ollama models via its /api/tags endpoint."""
    models = []
    try:
        with urllib.request.urlopen(f"{OLLAMA_HOST}/api/tags", timeout=3) as r:
            data = json.loads(r.read().decode())
    except Exception:
        return models  # Ollama not running / not installed — that's fine.

    for m in data.get("models", []):
        name = m.get("name")
        # Ollama reports the real parameter size in details; prefer it.
        detail = (m.get("details") or {}).get("parameter_size")
        size = parse_size_b(detail) or parse_size_b(name)
        models.append({
            "label": name, "model": name, "provider": "ollama",
            "api_key_env": None, "base_url": f"{OLLAMA_HOST}/v1",
            "size": size, "where": "local",
        })
    return models


def _http_get_json(url, token):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=6) as r:
        return json.loads(r.read().decode())


def discover_cloud():
    """List cloud models we can reach right now (live, so nothing is stale)."""
    models = []
    groq_key = os.environ.get("GROQ_API_KEY")
    if groq_key:
        try:
            data = _http_get_json("https://api.groq.com/openai/v1/models", groq_key)
            for m in data.get("data", []):
                mid = m.get("id")
                if not isinstance(mid, str) or not mid.strip():
                    continue
                models.append({
                    "label": mid, "model": mid, "provider": "groq",
                    "api_key_env": "GROQ_API_KEY", "base_url": None,
                    "size": parse_size_b(mid), "where": "cloud",
                })
        except Exception:
            pass
    openai_key = os.environ.get("OPENAI_API_KEY")
    if openai_key:
        try:
            data = _http_get_json("https://api.openai.com/v1/models", openai_key)
            for m in data.get("data", []):
                mid = m.get("id")
                if not isinstance(mid, str) or not mid.strip():
                    continue
                if mid.startswith(("gpt-", "o1", "o3", "o4")):  # skip embeddings/audio/etc
                    models.append({
                        "label": mid, "model": mid, "provider": "openai",
                        "api_key_env": "OPENAI_API_KEY", "base_url": None,
                        "size": parse_size_b(mid), "where": "cloud",
                    })
        except Exception:
            pass
    return models


def discover_models():
    # Local first (your default), then cloud.
    return discover_ollama() + discover_cloud()


# ============================================================
# THE PICKER
# ============================================================

def _fmt(m):
    size = f"{m['size']:g}B" if m["size"] else "size?"
    tag = "🖥  local " if m["where"] == "local" else "☁  cloud "
    return f"{tag} {m['provider']:<7} {m['label']:<34} ({size})"


def choose(models, role):
    print(f"\nPick the {role.upper()}:")
    for i, m in enumerate(models, 1):
        print(f"  {i:>2}. {_fmt(m)}")
    while True:
        raw = input(f"  {role} number > ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(models):
            return models[int(raw) - 1]
        print("  (type one of the numbers above)")


def judge_is_strong_enough(target, judge):
    """Enforce the one rule. Returns (ok: bool, needs_confirm: bool)."""
    t, j = target["size"], judge["size"]
    if t is not None and j is not None:
        return (j >= t, False)          # both known: hard rule
    return (True, True)                 # a size is unknown: allow after confirm


def pick_target_and_judge(models):
    while True:
        target = choose(models, "target (the model being attacked)")
        judge = choose(models, "judge (the smarter model that grades it)")
        ok, needs_confirm = judge_is_strong_enough(target, judge)
        if not ok:
            print(f"\n  ⛔  Judge '{judge['label']}' ({judge['size']:g}B) is smaller than "
                  f"target '{target['label']}' ({target['size']:g}B).")
            print("      The judge has to out-reason the target, or it shares its blind "
                  "spots. Pick a bigger judge.\n")
            continue
        if needs_confirm:
            print(f"\n  ⚠  I can't read the size of one of these from its name, so I can't "
                  f"auto-verify the rule.")
            print(f"      Target: {target['label']}   Judge: {judge['label']}")
            if input("      Is the judge at least as strong as the target? [y/N] ").strip().lower() != "y":
                print("      Okay — let's pick again.\n")
                continue
        return target, judge


# ============================================================
# SCAN LOOP (pretty console + same result shape as v1.1)
# ============================================================

def run_scan(target, judge, attack_library, rate_limit, max_tokens,
             retries=2, retry_delay=3, target_temperature=0.0,
             judge_temperature=0.1,
             judge_max_tokens=120):
    target_client = build_client(target)
    judge_client = build_client(judge)
    return run_full_scan(
        target_client,
        target["model"],
        judge_client,
        judge["model"],
        attack_library,
        rate_limit,
        max_tokens=max_tokens,
        retries=retries,
        retry_delay=retry_delay,
        target_temperature=target_temperature,
        judge_temperature=judge_temperature,
        judge_max_tokens=judge_max_tokens,
        verbose=True,
    )


def _selected_run_config(config, target, judge):
    """Bind picker-selected provider/model identity into report provenance."""

    selected = dict(config)
    for role, model in (("target", target), ("judge", judge)):
        block = dict(config.get(role, {}))
        for key in ("provider", "model", "api_key_env", "base_url"):
            if key in model:
                block[key] = model[key]
        selected[role] = block
    return selected


# ============================================================
# MAIN
# ============================================================

def main():
    print("=" * 60)
    print("  AGENTPROBE v1.2 — pick your models, then attack")
    print("=" * 60)

    models = discover_models()
    if not models:
        print("\nNo models found.")
        print("Set up local models first (2 minutes):")
        print("  1. Install Ollama:   brew install ollama   (or ollama.com)")
        print("  2. Start it:         ollama serve")
        print("  3. Pull two models:  ollama pull llama3.2:3b")
        print("                       ollama pull llama3.1:8b")
        print("Then run this again. (Or set GROQ_API_KEY / OPENAI_API_KEY for cloud models.)")
        sys.exit(1)

    target, judge = pick_target_and_judge(models)

    # Scan settings come from config.yaml (categories, rate limit); the
    # target/judge you just picked override whatever it says.
    try:
        config = load_config("config.yaml") if os.path.exists("config.yaml") else {"scan": {}, "output": {}}
    except (OSError, KeyError, ValueError) as exc:
        print(f"\n[ERROR] {exc}")
        raise SystemExit(1)
    attack_library = filter_attacks(config) if config.get("scan") is not None else None
    if not attack_library:
        from attacks.library import ATTACK_LIBRARY
        attack_library = ATTACK_LIBRARY
    rate_limit = config.get("scan", {}).get("rate_limit_seconds", 1)
    retries = config.get("scan", {}).get("retries", 2)
    retry_delay = config.get("scan", {}).get("retry_delay_seconds", 3)
    max_tokens = config.get("target", {}).get("max_tokens", 512)
    target_temperature = config.get("target", {}).get("temperature", 0.0)
    judge_temperature = config.get("judge", {}).get("temperature", 0.1)
    report_dir = config.get("output", {}).get("report_dir", "reports")
    report_format = config.get("output", {}).get("report_format", "both")

    results = run_scan(
        target, judge, attack_library, rate_limit, max_tokens,
        retries=retries, retry_delay=retry_delay,
        target_temperature=target_temperature,
        judge_temperature=judge_temperature,
        judge_max_tokens=judge.get("max_tokens", 120),
    )

    saved = None
    json_saved = None
    report_metadata = build_run_metadata(
        target["model"], judge["model"],
        target_provider=target.get("provider"),
        judge_provider=judge.get("provider"),
        config=_selected_run_config(config, target, judge),
        judge_prompt_version=JUDGE_PROMPT_VERSION,
        judge_prompt_sha256=JUDGE_PROMPT_SHA256,
    )
    json_report = build_json_report(
        results, target["model"], judge["model"], metadata=report_metadata
    )
    run_id = json_report["run"]["run_id"]
    if report_format in {"html", "both"}:
        print("\nGenerating HTML report (with Mitigation Map)...")
        html = generate_html_report(
            results, target["label"], judge["label"], metadata=report_metadata
        )
        saved = save_html_report(
            html, target["label"].replace("/", "_"), report_dir, run_id=run_id
        )
        print(f"Report saved to: {saved}")
    if report_format in {"json", "both"}:
        json_saved = save_json_report(
            json_report,
            target["label"].replace("/", "_"),
            report_dir,
        )
        print(f"JSON report saved to: {json_saved}")

    # Auto-open it in the browser.
    if saved:
        try:
            webbrowser.open("file://" + os.path.abspath(saved))
        except Exception:
            print(f"Open it yourself: open {saved}")


if __name__ == "__main__":
    main()
