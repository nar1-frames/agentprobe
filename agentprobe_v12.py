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
import re
import sys
import json
import time
import urllib.request
import webbrowser

# Reuse the v1.1 engine and report — one source of truth.
from agentprobe_v11 import (
    build_client, filter_attacks, load_config,
    send_prompt, assess_vulnerability, calculate_finding_severity,
)
from report_html_v11 import generate_html_report, save_html_report

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
    """Pull a parameter count in billions out of a string.

    Understands '8b', 'llama3.1:8b', '70B', '7.0B', 'qwen2.5-14b-instant'.
    Returns a float (billions) or None if it can't tell.
    """
    if not text:
        return None
    m = re.search(r"(\d+(?:\.\d+)?)\s*[bB]\b", text)
    if m:
        return float(m.group(1))
    # bare number followed by 'b' with no boundary, e.g. '8b-instant'
    m = re.search(r"(\d+(?:\.\d+)?)b", text.lower())
    return float(m.group(1)) if m else None


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

def run_scan(target, judge, attack_library, rate_limit, max_tokens):
    target_client = build_client(target)
    judge_client = build_client(judge)
    total = sum(len(v) for v in attack_library.values())

    print("\n" + "=" * 60)
    print(f"  TARGET: {target['label']}  ({target['provider']})")
    print(f"  JUDGE:  {judge['label']}  ({judge['provider']})")
    print(f"  {total} attacks across {len(attack_library)} categories")
    print("=" * 60)

    scan_results = {}
    for category, attacks in attack_library.items():
        print(f"\n[{category.upper()}] — {len(attacks)} prompts")
        rows = []
        for i, attack in enumerate(attacks):
            prompt, severity = attack["prompt"], attack["severity"]
            response = send_prompt(target_client, target["model"], prompt, max_tokens=max_tokens)
            verdict, reason, method = assess_vulnerability(
                target_client, target["model"], judge_client, judge["model"], prompt, response
            )
            finding = calculate_finding_severity(severity, verdict)
            rows.append((attack, response, verdict, finding, reason, method))

            emoji = VERDICT_EMOJI.get(verdict, "⚪")
            sev = f"[{finding}]" if finding else ""
            print(f"  {i+1}/{len(attacks)} {emoji} {verdict:<11} {sev:<10} "
                  f"via {method:<9} — {prompt[:40]}...")
            time.sleep(rate_limit)
        scan_results[category] = rows
    return scan_results


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
    config = load_config("config.yaml") if os.path.exists("config.yaml") else {"scan": {}, "output": {}}
    attack_library = filter_attacks(config) if config.get("scan") is not None else None
    if not attack_library:
        from attacks.library import ATTACK_LIBRARY
        attack_library = ATTACK_LIBRARY
    rate_limit = config.get("scan", {}).get("rate_limit_seconds", 1)
    max_tokens = config.get("target", {}).get("max_tokens", 512)
    report_dir = config.get("output", {}).get("report_dir", "reports")

    results = run_scan(target, judge, attack_library, rate_limit, max_tokens)

    print("\nGenerating HTML report (with Mitigation Map)...")
    html = generate_html_report(results, target["label"], judge["label"])
    saved = save_html_report(html, target["label"].replace("/", "_"), report_dir)
    print(f"Report saved to: {saved}")

    # Auto-open it in the browser.
    try:
        webbrowser.open("file://" + os.path.abspath(saved))
    except Exception:
        print(f"Open it yourself: open {saved}")


if __name__ == "__main__":
    main()
