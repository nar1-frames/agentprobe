#!/usr/bin/env python3
# ============================================================
# STEP C — Run the judges over the frozen corpus
# ============================================================
# For every response in corpus.jsonl, run each judge CONFIG
# (model x temperature) k times, and log EVERY verdict — not just
# the majority vote. You cannot analyse variance you threw away.
#
# What this unlocks
# -----------------
#   RQ2 (reliability): k repeats of the same config let you measure
#        self-agreement — does the judge give the same answer when
#        you ask it again? Fleiss' kappa over the k runs quantifies it.
#   RQ4 (judge strength): put a strong judge (e.g. llama-3.3-70b) and
#        a weak/same-family judge (the 8B target itself) in the config
#        list, and you can compare each against the human labels.
#   Temperature sweep: 0.0 vs 0.7 tells you whether sampling noise,
#        not model choice, drives the disagreement.
#
# IMPORTANT: this step judges EVERY response directly. That is on
# purpose — the paper studies the judge in isolation, so we do NOT
# route through the keyword short-circuit here. (The keyword verdict
# is still recorded in the corpus, so RQ3 — keyword vs judge — is a
# join between the two files, not a thing to bake in now.)
#
# Usage
# -----
#   python -m research.run_judges                      # judges from config
#   python -m research.run_judges --k 5 --temps 0.0,0.7
#   python -m research.run_judges --judges llama-3.3-70b-versatile,llama-3.1-8b-instant
#
# Each line of judgements.jsonl:
#   {
#     "response_id", "category", "attack_index", "target_model",
#     "judge_provider", "judge_model", "temperature", "run_idx",
#     "judge_verdict_raw", "verdict", "reason", "raw", "error"
#   }
# ============================================================

import argparse
import os
import time

from research._common import (
    load_config, build_client, read_jsonl, append_jsonl, write_jsonl,
)
from agentprobe.detection import llm_judge


def judge_configs_from_args(config, args):
    """Build the list of (provider_cfg, model, temperature) judge configs."""
    base_judge = config["judge"]
    models = ([m.strip() for m in args.judges.split(",")] if args.judges
              else [base_judge["model"]])
    temps = [float(t) for t in args.temps.split(",")] if args.temps else [0.1]
    configs = []
    for model in models:
        for temp in temps:
            configs.append((base_judge, model, temp))
    return configs


def already_done(existing, rid, model, temp, run_idx):
    return (rid, model, temp, run_idx) in existing


def load_done_keys(path):
    """Resume support: which (response, judge, temp, run) tuples already exist."""
    if not os.path.exists(path):
        return set()
    keys = set()
    for r in read_jsonl(path):
        keys.add((r["response_id"], r["judge_model"],
                  float(r["temperature"]), r["run_idx"]))
    return keys


def main():
    ap = argparse.ArgumentParser(description="Run judges over the corpus (Step C).")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--corpus", default="data/corpus.jsonl")
    ap.add_argument("--out", default="data/judgements.jsonl")
    ap.add_argument("--k", type=int, default=5, help="repeats per (response, judge, temp)")
    ap.add_argument("--judges", default=None,
                    help="comma-separated judge model names (default: config judge.model)")
    ap.add_argument("--temps", default=None,
                    help="comma-separated temperatures, e.g. 0.0,0.7 (default: 0.1)")
    ap.add_argument("--resume", action="store_true",
                    help="skip (response,judge,temp,run) tuples already in --out")
    args = ap.parse_args()

    config = load_config(args.config)
    corpus = read_jsonl(args.corpus)
    if not corpus:
        raise SystemExit(f"No corpus at {args.corpus}. Run gen_corpus first.")

    configs = judge_configs_from_args(config, args)
    rate_limit = config.get("scan", {}).get("rate_limit_seconds", 1)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    done = load_done_keys(args.out) if args.resume else set()
    if not args.resume and os.path.exists(args.out):
        os.remove(args.out)

    total_calls = len(corpus) * len(configs) * args.k
    print(f"[judges] corpus={len(corpus)}  configs={len(configs)}  k={args.k}")
    print(f"[judges] planned judge calls: {total_calls}")

    # Build one client per distinct judge model (reused across temps/runs).
    clients = {}
    for base_judge, model, _temp in configs:
        if model not in clients:
            clients[model] = build_client({**base_judge, "model": model})

    call = 0
    for base_judge, model, temp in configs:
        provider = base_judge.get("provider", "groq")
        client = clients[model]
        for row in corpus:
            for run_idx in range(args.k):
                call += 1
                if args.resume and (row["response_id"], model, temp, run_idx) in done:
                    continue
                jr = llm_judge(client, model, row["attack_prompt"],
                               row["response"], temperature=temp)
                append_jsonl(args.out, {
                    "response_id": row["response_id"],
                    "category": row["category"],
                    "attack_index": row["attack_index"],
                    "target_model": row["target_model"],
                    "judge_provider": provider,
                    "judge_model": model,
                    "temperature": temp,
                    "run_idx": run_idx,
                    "judge_verdict_raw": jr.judge_verdict,
                    "verdict": jr.verdict,
                    "reason": jr.reason,
                    "raw": jr.raw,
                    "error": jr.error,
                })
                if call % 20 == 0 or call == total_calls:
                    print(f"  [{call}/{total_calls}] {model}@{temp} "
                          f"{row['category']}/{row['attack_index']} -> {jr.verdict}")
                time.sleep(rate_limit)

    print(f"\nDone. Judgements at {args.out}. Next: label (research.label) then analyze.")


if __name__ == "__main__":
    main()
