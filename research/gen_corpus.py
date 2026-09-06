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
#     "target_temperature",
#     "response", "keyword_verdict", "keyword_decisive",
#     "refusal_hits", "compliance_hits", "error"
#   }
# ============================================================

import argparse
import math
import os
import time

from research._common import (
    load_config, build_client, response_id, read_jsonl, write_jsonl,
)
from attacks.library import ATTACK_LIBRARY
from agentprobe.detection import keyword_check, sanitize_error
from agentprobe.reliability import is_retryable_error


def send_prompt(client, model, prompt, max_tokens=512, temperature=0.0,
                retries=2, delay=3):
    """One target call, with retry/backoff. Returns (text, error_or_None)."""
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
            return content, None
        except Exception as e:  # noqa: BLE001
            last_err = sanitize_error(e)
            if attempt < retries and is_retryable_error(e):
                time.sleep(delay)
            else:
                break
    return None, f"request failed after {retries + 1} attempts: {last_err}"


def iter_attacks():
    for category, attacks in ATTACK_LIBRARY.items():
        for idx, attack in enumerate(attacks):
            yield category, idx, attack


def generate(target_cfg, model, out_path, max_tokens, target_temperature,
             rate_limit, retries=2, retry_delay=3, records_by_id=None):
    client = build_client({**target_cfg, "model": model})
    provider = target_cfg.get("provider", "groq")
    total = sum(len(v) for v in ATTACK_LIBRARY.values())
    print(f"[corpus] target={provider}/{model}  prompts={total}  -> {out_path}")

    done = 0
    for category, idx, attack in iter_attacks():
        rid = response_id(category, idx, model)
        existing = (records_by_id or {}).get(rid)
        if existing is not None:
            same_settings = (
                existing.get("target_model") == model
                and existing.get("max_tokens") == max_tokens
                and existing.get("target_temperature") == target_temperature
                and existing.get("attack_prompt") == attack["prompt"]
            )
            if not same_settings:
                raise ValueError(
                    f"existing corpus row {rid} does not match the requested "
                    "target settings or attack prompt"
                )
            if not existing.get("error"):
                print(f"  [resume] {category}/{idx} already complete")
                continue
        prompt = attack["prompt"]
        text, err = send_prompt(
            client, model, prompt, max_tokens=max_tokens,
            temperature=target_temperature,
            retries=retries, delay=retry_delay,
        )
        response = text if text is not None else ""
        kw = keyword_check(response)

        record = {
            "response_id": rid,
            "category": category,
            "attack_index": idx,
            "severity": attack["severity"],
            "attack_prompt": prompt,
            "attack_description": attack.get("description", ""),
            "target_provider": provider,
            "target_model": model,
            "max_tokens": max_tokens,
            "target_temperature": target_temperature,
            "response": response,
            "keyword_verdict": kw.verdict,
            "keyword_decisive": kw.decisive,
            "refusal_hits": kw.refusal_hits,
            "compliance_hits": kw.compliance_hits,
            "error": err,
        }
        if records_by_id is not None:
            records_by_id[rid] = record
            # Rewrite atomically after every response. This makes an
            # interrupted corpus run resumable without duplicate response IDs.
            write_jsonl(out_path, records_by_id.values())
        else:
            # The public function remains usable without the CLI checkpoint.
            current = read_jsonl(out_path) if os.path.exists(out_path) else []
            current.append(record)
            write_jsonl(out_path, current)
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
    ap.add_argument("--target-temperature", type=float, default=None,
                    help="override target.temperature (default: config or 0.0)")
    ap.add_argument("--append", action="store_true",
                    help="append to an existing corpus instead of overwriting")
    ap.add_argument("--overwrite", action="store_true",
                    help="explicitly replace an existing corpus (destructive)")
    args = ap.parse_args()

    if args.append and args.overwrite:
        raise SystemExit("--append and --overwrite are mutually exclusive")

    config = load_config(args.config)
    target_cfg = config["target"]
    max_tokens = args.max_tokens if args.max_tokens is not None else target_cfg.get("max_tokens", 512)
    if max_tokens < 1 or max_tokens > 131072:
        raise SystemExit("--max-tokens must be between 1 and 131072")
    target_temperature = (
        args.target_temperature
        if args.target_temperature is not None
        else target_cfg.get("temperature", 0.0)
    )
    if not math.isfinite(target_temperature) or not 0 <= target_temperature <= 2:
        raise SystemExit("--target-temperature must be between 0 and 2")
    rate_limit = config.get("scan", {}).get("rate_limit_seconds", 1)
    retries = config.get("scan", {}).get("retries", 2)
    retry_delay = config.get("scan", {}).get("retry_delay_seconds", 3)

    models = ([m.strip() for m in args.models.split(",")] if args.models
              else [target_cfg["model"]])

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    if os.path.exists(args.out) and not args.append and not args.overwrite:
        raise SystemExit(
            f"Refusing to replace existing corpus {args.out}; use --append, "
            "--overwrite, or a new --out path"
        )
    records_by_id = {}
    if args.append and os.path.exists(args.out):
        try:
            for row in read_jsonl(args.out):
                rid = row.get("response_id")
                if not isinstance(rid, str) or not rid:
                    raise ValueError("existing corpus contains a row without response_id")
                if rid in records_by_id:
                    raise ValueError(f"existing corpus contains duplicate response_id {rid}")
                records_by_id[rid] = row
        except (OSError, ValueError) as exc:
            raise SystemExit(f"Cannot resume corpus safely: {exc}")
    elif not args.append:
        # A fresh run starts from an empty in-memory checkpoint and writes its
        # first record atomically below.
        records_by_id = {}

    for model in models:
        generate(
            target_cfg, model, args.out, max_tokens, target_temperature,
            rate_limit, retries, retry_delay, records_by_id,
        )

    print(f"\nDone. Corpus at {args.out}. Next: python -m research.run_judges")


if __name__ == "__main__":
    main()
