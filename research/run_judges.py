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
#     "corpus_sha256", "judge_verdict_raw", "verdict", "reason", "raw", "error"
#   }
# ============================================================

import argparse
import json
import math
import os
import tempfile
import time

from research._common import (
    load_config, build_client, provider_config_digest, read_jsonl, append_jsonl,
    canonical_digest,
)
from agentprobe.detection import JUDGE_PROMPT_SHA256, JUDGE_PROMPT_VERSION, llm_judge
from research.protocol import DEFAULT_MANIFEST_PATH, load_manifest, manifest_digest
from attacks.library import ATTACK_LIBRARY
from research.validate import validate_dataset


def judge_configs_from_args(config, args, manifest=None):
    """Build the list of (provider_cfg, model, temperature) judge configs."""
    base_judge = config["judge"]
    if manifest and base_judge.get("provider", "groq") != manifest["judge_provider"]:
        raise ValueError(
            "judge provider must match the manifest; use --manifest \"\" "
            "for an exploratory deviation"
        )
    if manifest and not args.judges and not args.temps:
        return [
            (base_judge, judge["model"], float(judge["temperature"]))
            for judge in manifest["judges"]
        ]
    models = ([m.strip() for m in args.judges.split(",")] if args.judges
              else [judge["model"] for judge in manifest["judges"]]
              if manifest else [base_judge["model"]])
    temps = ([float(t) for t in args.temps.split(",")] if args.temps
             else [float(judge["temperature"]) for judge in manifest["judges"]]
             if manifest else [0.1])
    temps = list(dict.fromkeys(temps))
    if not models or any(not model for model in models):
        raise ValueError("judge model list must contain non-empty names")
    if not temps or any(not math.isfinite(temp) or not 0 <= temp <= 2 for temp in temps):
        raise ValueError("judge temperatures must be between 0 and 2")
    configs = []
    for model in models:
        for temp in temps:
            configs.append((base_judge, model, temp))
    return configs


def validate_manifest_overrides(args, manifest):
    """Reject accidental judge-matrix deviations before any provider call."""

    if not manifest:
        return
    expected_models = {judge["model"] for judge in manifest["judges"]}
    expected_temps = {float(judge["temperature"]) for judge in manifest["judges"]}
    if args.judges is not None:
        models = [model.strip() for model in args.judges.split(",")]
        if set(models) != expected_models or len(models) != len(expected_models):
            raise ValueError(
                "--judges must match the manifest matrix; use --manifest \"\" "
                "for an exploratory deviation"
            )
    if args.temps is not None:
        try:
            temperatures = [float(value) for value in args.temps.split(",")]
        except (TypeError, ValueError) as exc:
            raise ValueError("--temps must contain numeric values") from exc
        if (set(temperatures) != expected_temps
                or len(temperatures) != len(expected_temps)):
            raise ValueError(
                "--temps must match the manifest matrix; use --manifest \"\" "
                "for an exploratory deviation"
            )
    if args.k is not None and args.k != manifest["repeats"]:
        raise ValueError(
            "--k must match the manifest repeat count; use --manifest \"\" "
            "for an exploratory deviation"
        )


def already_done(existing, rid, model, temp, run_idx):
    return (rid, model, temp, run_idx) in existing


def load_done_keys(path, corpus_sha256=None, expected_judge_prompt_version=None,
                   expected_judge_prompt_sha256=None,
                   expected_protocol_manifest_sha256=None,
                   expected_judge_max_tokens=None,
                   expected_judge_config_sha256=None):
    """Return existing evidence keys when bound to the frozen corpus.

    Failed rows are existing evidence too.  They remain in the active file
    until ``--repair-errors`` explicitly archives them; treating them as
    already present prevents a plain ``--resume`` from appending duplicate
    keys and obscuring the original failure.
    """
    if not os.path.exists(path):
        return set()
    keys = set()
    seen = set()
    for r in read_jsonl(path):
        if not isinstance(r, dict):
            raise ValueError("existing judge evidence contains a non-object row")
        if corpus_sha256 is not None and r.get("corpus_sha256") != corpus_sha256:
            raise ValueError(
                "existing judge evidence is missing or has a different corpus_sha256"
            )
        if (expected_judge_prompt_version is not None
                and r.get("judge_prompt_version") != expected_judge_prompt_version):
            raise ValueError(
                "existing judge evidence has a different or missing judge prompt version; "
                "use --overwrite to collect fresh evidence"
            )
        if (expected_judge_prompt_sha256 is not None
                and r.get("judge_prompt_sha256") != expected_judge_prompt_sha256):
            raise ValueError(
                "existing judge evidence has a different or missing judge prompt digest; "
                "use --overwrite to collect fresh evidence"
            )
        if (expected_protocol_manifest_sha256 is not None
                and r.get("protocol_manifest_sha256") != expected_protocol_manifest_sha256):
            raise ValueError(
                "existing judge evidence has a different or missing protocol manifest digest; "
                "use --overwrite to collect fresh evidence"
            )
        if (expected_judge_max_tokens is not None
                and r.get("judge_max_tokens") != expected_judge_max_tokens):
            raise ValueError(
                "existing judge evidence has a different or missing judge token budget; "
                "use --overwrite to collect fresh evidence"
            )
        try:
            key = (r["response_id"], r["judge_model"],
                   float(r["temperature"]), r["run_idx"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("existing judge evidence contains a malformed key") from exc
        try:
            duplicate = key in seen
            if duplicate:
                raise ValueError(f"existing judge evidence contains duplicate key {key}")
            seen.add(key)
        except TypeError as exc:
            raise ValueError("existing judge evidence contains an unhashable key") from exc
        if expected_judge_config_sha256 is not None:
            config_key = (key[1], key[2])
            expected_digest = expected_judge_config_sha256.get(config_key)
            if expected_digest is None or r.get("judge_config_sha256") != expected_digest:
                raise ValueError(
                    "existing judge evidence has a different or missing provider "
                    "configuration digest; use --overwrite to collect fresh evidence"
                )
        keys.add(key)
    return keys


def _write_jsonl_atomic(path, records):
    """Replace a JSONL file atomically after an explicit repair operation."""

    directory = os.path.dirname(path) or "."
    fd, temporary = tempfile.mkstemp(prefix=".agentprobe-repair-", suffix=".jsonl", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for record in records:
                f.write(json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def repair_error_rows(path):
    """Archive failed rows and remove them from the active resume set."""

    rows = read_jsonl(path)
    errors = [row for row in rows if row.get("error")]
    if not errors:
        return 0, None
    active = [row for row in rows if not row.get("error")]
    archive = f"{path}.errors.jsonl"
    existing = read_jsonl(archive) if os.path.exists(archive) else []
    _write_jsonl_atomic(archive, existing + errors)
    _write_jsonl_atomic(path, active)
    return len(errors), archive


def main():
    ap = argparse.ArgumentParser(description="Run judges over the corpus (Step C).")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--corpus", default="data/corpus.jsonl")
    ap.add_argument("--out", default="data/judgements.jsonl")
    ap.add_argument("--k", type=int, default=None, help="repeats per (response, judge, temp)")
    ap.add_argument(
        "--manifest", default=DEFAULT_MANIFEST_PATH,
        help="study protocol used for default judge matrix and repeat count",
    )
    ap.add_argument("--judges", default=None,
                    help="comma-separated judge model names (default: study manifest)")
    ap.add_argument("--temps", default=None,
                    help="comma-separated temperatures, e.g. 0.0,0.7 (default: study manifest)")
    ap.add_argument("--resume", action="store_true",
                    help="skip (response,judge,temp,run) tuples already in --out")
    ap.add_argument("--overwrite", action="store_true",
                    help="explicitly replace existing judge evidence (destructive)")
    ap.add_argument(
        "--repair-errors", action="store_true",
        help="archive failed rows and retry them (requires --resume)",
    )
    ap.add_argument(
        "--fail-on-error", action="store_true",
        help="exit 3 after writing evidence if any judge call failed",
    )
    args = ap.parse_args()
    if args.resume and args.overwrite:
        raise SystemExit("--resume and --overwrite are mutually exclusive")
    if args.repair_errors and not args.resume:
        raise SystemExit("--repair-errors requires --resume")
    manifest = None
    if args.manifest and os.path.exists(args.manifest):
        try:
            manifest = load_manifest(args.manifest)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise SystemExit(f"Invalid study manifest: {exc}")
    try:
        validate_manifest_overrides(args, manifest)
    except ValueError as exc:
        raise SystemExit(str(exc))
    k = args.k if args.k is not None else (manifest or {}).get("repeats", 5)
    if k < 1:
        raise SystemExit("--k must be at least 1")

    config = load_config(args.config)
    corpus = read_jsonl(args.corpus)
    if not corpus:
        raise SystemExit(f"No corpus at {args.corpus}. Run gen_corpus first.")
    corpus_validation = validate_dataset(corpus, attack_library=ATTACK_LIBRARY)
    if not corpus_validation["valid"]:
        for error in corpus_validation["errors"]:
            print(f"ERROR: {error}")
        raise SystemExit("Corpus validation failed; repair or regenerate it before judging.")
    for warning in corpus_validation["warnings"]:
        print(f"WARNING: {warning}")
    corpus_sha256 = canonical_digest(corpus)

    try:
        configs = judge_configs_from_args(config, args, manifest)
    except ValueError as exc:
        raise SystemExit(str(exc))
    rate_limit = config.get("scan", {}).get("rate_limit_seconds", 1)
    retries = config.get("scan", {}).get("retries", 2)
    retry_delay = config.get("scan", {}).get("retry_delay_seconds", 3)
    base_judge = config["judge"]
    judge_max_tokens = (manifest or {}).get(
        "judge_max_tokens", base_judge.get("max_tokens", 120)
    )
    if (isinstance(judge_max_tokens, bool) or not isinstance(judge_max_tokens, int)
            or not 1 <= judge_max_tokens <= 131072):
        raise SystemExit("judge max token budget must be an integer between 1 and 131072")
    protocol_manifest_sha256 = manifest_digest(manifest) if manifest else None
    expected_judge_config_sha256 = None
    if manifest:
        expected_judge_config_sha256 = {
            (model, float(temp)): provider_config_digest({
                **base_judge,
                "model": model,
                "temperature": temp,
                "max_tokens": judge_max_tokens,
            })
            for base_judge, model, temp in configs
        }

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    if os.path.exists(args.out) and not args.resume and not args.overwrite:
        raise SystemExit(
            f"Refusing to replace existing judge evidence {args.out}; use --resume, "
            "--overwrite, or a new --out path"
        )
    if args.repair_errors and os.path.exists(args.out):
        try:
            repaired, archive = repair_error_rows(args.out)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise SystemExit(f"Could not repair judge evidence: {exc}")
        if repaired:
            print(f"[judges] archived {repaired} failed rows to {archive}")
    if args.resume:
        try:
            done = load_done_keys(
                args.out,
                corpus_sha256,
                expected_judge_prompt_version=(manifest or {}).get("judge_prompt_version"),
                expected_judge_prompt_sha256=(manifest or {}).get("judge_prompt_sha256"),
                expected_protocol_manifest_sha256=protocol_manifest_sha256,
                expected_judge_max_tokens=judge_max_tokens if manifest else None,
                expected_judge_config_sha256=expected_judge_config_sha256,
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise SystemExit(f"Cannot resume judge evidence safely: {exc}")
    else:
        done = set()
    if args.overwrite and os.path.exists(args.out):
        os.remove(args.out)

    total_calls = len(corpus) * len(configs) * k
    print(f"[judges] corpus={len(corpus)}  configs={len(configs)}  k={k}")
    print(f"[judges] corpus_sha256={corpus_sha256}")
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
            if row.get("error"):
                # The target did not produce a response to judge. Leaving the
                # group absent makes the missingness visible to RQ2 and the
                # publication gate instead of disguising an outage as judge
                # behavior.
                continue
            for run_idx in range(k):
                call += 1
                if args.resume and (row["response_id"], model, temp, run_idx) in done:
                    continue
                jr = llm_judge(client, model, row["attack_prompt"],
                               row["response"], temperature=temp,
                               max_tokens=judge_max_tokens,
                               retries=retries, delay=retry_delay)
                judge_config_sha256 = provider_config_digest({
                    **base_judge,
                    "model": model,
                    "temperature": temp,
                    "max_tokens": judge_max_tokens,
                })
                append_jsonl(args.out, {
                    "response_id": row["response_id"],
                    "category": row["category"],
                    "attack_index": row["attack_index"],
                    "target_model": row["target_model"],
                    "judge_provider": provider,
                    "judge_model": model,
                    "judge_prompt_version": JUDGE_PROMPT_VERSION,
                    "judge_prompt_sha256": JUDGE_PROMPT_SHA256,
                    "judge_config_sha256": judge_config_sha256,
                    "judge_max_tokens": judge_max_tokens,
                    "protocol_manifest_sha256": protocol_manifest_sha256,
                    "corpus_sha256": corpus_sha256,
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

    judge_rows = read_jsonl(args.out) if os.path.exists(args.out) else []
    operational_errors = sum(
        bool(row.get("error")) for row in judge_rows
        if isinstance(row, dict)
    )
    if args.fail_on_error and operational_errors:
        print(f"ERROR: {operational_errors} judge call(s) recorded an operational error")
        raise SystemExit(3)
    print(f"\nDone. Judgements at {args.out}. Next: label (research.label) then analyze.")


if __name__ == "__main__":
    main()
