#!/usr/bin/env python3
# ============================================================
# STEP A — Generate the response corpus
# ============================================================
# Run the 49 attacks against one or more TARGET models and save
# every raw response to corpus.jsonl. No judging happens here.
#
# Why corpus and judge are separated (the key methods decision)
# -------------------------------------------------------------
# Hitting the target is the expensive, non-reproducible part: it
# costs tokens and the model may change under you. The judge, by
# contrast, you want to run MANY times (k repeats, several judge
# models, two temperatures). If the two were fused you would have
# to re-hit every target every time you wanted to re-judge — and
# your human labels would have nothing stable to attach to.
#
# So: freeze the corpus ONCE. Then judge it, label it, and
# re-judge it as many times as the analysis needs, all against the
# same fixed set of responses. This single decision is what makes
# RQ2 (reliability across runs) and RQ4 (judge strength) even
# measurable.
#
# Usage
# -----
#   python -m research.gen_corpus                # models from --models or config target
#   python -m research.gen_corpus --models llama-3.1-8b-instant,gemma2-9b-it
#   python -m research.gen_corpus --out data/corpus.jsonl --max-tokens 512
#
# Each line of corpus.jsonl:
#   {
#     "response_id", "category", "attack_index", "severity",
#     "attack_prompt", "attack_description",
#     "target_provider", "target_model", "max_tokens",
#     "response", "keyword_verdict", "keyword_decisive",
#     "refusal_hits", "compliance_hits", "error"
#   }
# ============================================================

import argparse
import os
import time

from research._common import (
    load_config, build_client, response_id, append_jsonl,
)
from attacks.library import ATTACK_LIBRARY
from agentprobe.detection import keyword_check


def send_prompt(client, model, prompt, max_tokens=512, retries=2, delay=3):
    """One target call, with retry/backoff. Returns (text, error_or_None)."""
    last_err = None
    for attempt in range(retries + 1):
        try:
            result = client.chat.completions.create(
                messages=[{"role": "user", "content": prompt}],
                model=model,
                max_tokens=max_tokens,
            )
            return result.choices[0].message.content, None
        except Exception as e:  # noqa: BLE001
            last_err = e
            if attempt < retries:
                time.sleep(delay)
    return None, f"request failed after {retries + 1} attempts: {last_err}"


def iter_attacks():
    for category, attacks in ATTACK_LIBRARY.items():
        for idx, attack in enumerate(attacks):
            yield category, idx, attack


def generate(target_cfg, model, out_path, max_tokens, rate_limit):
    client = build_client({**target_cfg, "model": model})
    provider = target_cfg.get("provider", "groq")
    total = sum(len(v) for v in ATTACK_LIBRARY.values())
    print(f"[corpus] target={provider}/{model}  prompts={total}  -> {out_path}")

    done = 0
    for category, idx, attack in iter_attacks():
        rid = response_id(category, idx, model)
        prompt = attack["prompt"]
        text, err = send_prompt(client, model, prompt, max_tokens=max_tokens)
        response = text if text is not None else ""
        kw = keyword_check(response)

        append_jsonl(out_path, {
            "response_id": rid,
            "category": category,
            "attack_index": idx,
            "severity": attack["severity"],
            "attack_prompt": prompt,
            "attack_description": attack.get("description", ""),
            "target_provider": provider,
            "target_model": model,
            "max_tokens": max_tokens,
            "response": response,
            "keyword_verdict": kw.verdict,
            "keyword_decisive": kw.decisive,
            "refusal_hits": kw.refusal_hits,
            "compliance_hits": kw.compliance_hits,
            "error": err,
        })
        done += 1
        flag = "ERR" if err else kw.verdict[:4]
        print(f"  [{done}/{total}] {category}/{idx} [{flag}] {prompt[:44]}...")
        time.sleep(rate_limit)
    print(f"[corpus] wrote {done} responses for {model}")


def main():
    ap = argparse.ArgumentParser(description="Generate the response corpus (Step A).")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--models", default=None,
                    help="comma-separated target model names (default: config target.model)")
    ap.add_argument("--out", default="data/corpus.jsonl")
    ap.add_argument("--max-tokens", type=int, default=None,
                    help="override target.max_tokens (default: config or 512)")
    ap.add_argument("--append", action="store_true",
                    help="append to an existing corpus instead of overwriting")
    args = ap.parse_args()

    config = load_config(args.config)
    target_cfg = config["target"]
    max_tokens = args.max_tokens or target_cfg.get("max_tokens", 512)
    rate_limit = config.get("scan", {}).get("rate_limit_seconds", 1)

    models = ([m.strip() for m in args.models.split(",")] if args.models
              else [target_cfg["model"]])

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    if not args.append and os.path.exists(args.out):
        os.remove(args.out)

    for model in models:
        generate(target_cfg, model, args.out, max_tokens, rate_limit)

    print(f"\nDone. Corpus at {args.out}. Next: python -m research.run_judges")


if __name__ == "__main__":
    main()
