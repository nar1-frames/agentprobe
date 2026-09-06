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
#   python -m research.gen_corpus                # models/settings from manifest
#   python -m research.gen_corpus --models openai/gpt-oss-20b,gemma2-9b-it
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
import json
import math
import os
import time

from research._common import (
    load_config, build_client, provider_config_digest, response_id, read_jsonl,
    write_jsonl,
)
from agentprobe.providers import preflight_model
from research.protocol import DEFAULT_MANIFEST_PATH, load_manifest, manifest_digest
from attacks.library import ATTACK_LIBRARY
from agentprobe.detection import keyword_check, sanitize_error
from agentprobe.reliability import is_retryable_error


def send_prompt(client, model, prompt, max_tokens=512, temperature=0.0,
                retries=2, delay=3, reasoning_effort=None, system_prompt=None):
    """One target call, with retry/backoff. Returns (text, error_or_None)."""
    last_err = None
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
            content = result.choices[0].message.content
            if not isinstance(content, str) or not content.strip():
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


def resolve_generation_plan(target_cfg, models_arg=None, max_tokens_arg=None,
                            temperature_arg=None, manifest=None):
    """Resolve and validate corpus settings before any provider call."""

    manifest_corpus = (manifest or {}).get("corpus", {})
    if models_arg is None:
        models = list(manifest_corpus.get("target_models", [])) or [target_cfg["model"]]
    else:
        models = [model.strip() for model in models_arg.split(",")]
    if not models or any(not model for model in models) or len(set(models)) != len(models):
        raise ValueError("target model list must contain unique non-empty names")

    max_tokens = (
        max_tokens_arg if max_tokens_arg is not None
        else manifest_corpus.get("target_max_tokens", target_cfg.get("max_tokens", 512))
    )
    target_temperature = (
        temperature_arg if temperature_arg is not None
        else manifest_corpus.get("target_temperature", target_cfg.get("temperature", 0.0))
    )

    if manifest:
        expected_provider = manifest_corpus["target_provider"]
        actual_provider = target_cfg.get("provider", "groq")
        if actual_provider != expected_provider:
            raise ValueError(
                "target provider must match the manifest; use --manifest \"\" "
                "for an exploratory deviation"
            )
        expected_models = set(manifest_corpus["target_models"])
        if set(models) != expected_models or len(models) != len(expected_models):
            raise ValueError(
                "--models must match the manifest target scope; use --manifest "
                "\"\" for an exploratory deviation"
            )
        if max_tokens != manifest_corpus["target_max_tokens"]:
            raise ValueError(
                "--max-tokens must match the manifest; use --manifest \"\" "
                "for an exploratory deviation"
            )
        if float(target_temperature) != float(manifest_corpus["target_temperature"]):
            raise ValueError(
                "--target-temperature must match the manifest; use --manifest "
                "\"\" for an exploratory deviation"
            )

    if isinstance(max_tokens, bool) or not isinstance(max_tokens, int):
        raise ValueError("--max-tokens must be an integer")
    if max_tokens < 1 or max_tokens > 131072:
        raise ValueError("--max-tokens must be between 1 and 131072")
    target_temperature = float(target_temperature)
    if not math.isfinite(target_temperature) or not 0 <= target_temperature <= 2:
        raise ValueError("--target-temperature must be between 0 and 2")
    return models, max_tokens, target_temperature


def generate(target_cfg, model, out_path, max_tokens, target_temperature,
             rate_limit, retries=2, retry_delay=3, records_by_id=None,
             protocol_manifest_sha256=None, reasoning_effort=None,
             system_prompt=None):
    provider = target_cfg.get("provider", "groq")
    target_config_sha256 = provider_config_digest({
        **target_cfg,
        "model": model,
        "max_tokens": max_tokens,
        "temperature": target_temperature,
    })
    collected_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    total = sum(len(v) for v in ATTACK_LIBRARY.values())
    print(f"[corpus] target={provider}/{model}  prompts={total}  -> {out_path}")

    done = 0
    client = None
    for category, idx, attack in iter_attacks():
        rid = response_id(category, idx, model)
        existing = (records_by_id or {}).get(rid)
        if existing is not None:
            same_settings = (
                existing.get("target_model") == model
                and existing.get("max_tokens") == max_tokens
                and existing.get("target_temperature") == target_temperature
                and existing.get("target_reasoning_effort") == reasoning_effort
                and existing.get("target_system_prompt") == system_prompt
                and existing.get("attack_prompt") == attack["prompt"]
                and existing.get("target_config_sha256") == target_config_sha256
                and existing.get("protocol_manifest_sha256") == protocol_manifest_sha256
                )
            if not same_settings:
                raise ValueError(
                    f"existing corpus row {rid} does not match the requested "
                    "target settings or attack prompt"
                )
            if not existing.get("error"):
                print(f"  [resume] {category}/{idx} already complete")
                continue
        if client is None:
            client = build_client({**target_cfg, "model": model})
            preflight_model(client, model)
        prompt = attack["prompt"]
        text, err = send_prompt(
            client, model, prompt, max_tokens=max_tokens,
            temperature=target_temperature,
            retries=retries, delay=retry_delay,
            reasoning_effort=reasoning_effort,
            system_prompt=system_prompt,
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
            "target_config_sha256": target_config_sha256,
            "protocol_manifest_sha256": protocol_manifest_sha256,
            "collected_at": collected_at,
            "max_tokens": max_tokens,
            "target_temperature": target_temperature,
            "target_reasoning_effort": reasoning_effort,
            "target_system_prompt": system_prompt,
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
    ap.add_argument(
        "--manifest", default=DEFAULT_MANIFEST_PATH,
        help="study protocol for default target scope/settings; use an empty value to disable",
    )
    ap.add_argument("--max-tokens", type=int, default=None,
                    help="override target.max_tokens (default: config or 512)")
    ap.add_argument("--target-temperature", type=float, default=None,
                    help="override target.temperature (default: config or 0.0)")
    ap.add_argument("--append", action="store_true",
                    help="append to an existing corpus instead of overwriting")
    ap.add_argument("--overwrite", action="store_true",
                    help="explicitly replace an existing corpus (destructive)")
    ap.add_argument(
        "--fail-on-error", action="store_true",
        help="exit 3 after writing the corpus if any target call failed",
    )
    args = ap.parse_args()

    if args.append and args.overwrite:
        raise SystemExit("--append and --overwrite are mutually exclusive")

    manifest = None
    if args.manifest:
        try:
            manifest = load_manifest(args.manifest)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise SystemExit(f"Invalid study manifest: {exc}")

    config = load_config(args.config)
    target_cfg = config["target"]
    try:
        models, max_tokens, target_temperature = resolve_generation_plan(
            target_cfg, args.models, args.max_tokens, args.target_temperature, manifest,
        )
    except (TypeError, ValueError) as exc:
        raise SystemExit(str(exc))
    rate_limit = config.get("scan", {}).get("rate_limit_seconds", 1)
    retries = config.get("scan", {}).get("retries", 2)
    retry_delay = config.get("scan", {}).get("retry_delay_seconds", 3)
    target_reasoning_effort = target_cfg.get("reasoning_effort")
    if manifest and target_reasoning_effort != manifest.get("target_reasoning_effort"):
        raise SystemExit(
            "target reasoning_effort must match the manifest; use --manifest \"\" "
            "for an exploratory deviation"
        )
    target_system_prompt = target_cfg.get("system_prompt")
    if manifest and target_system_prompt != manifest.get("corpus", {}).get("target_system_prompt"):
        raise SystemExit(
            "target system_prompt must match the manifest; use --manifest \"\" "
            "for an exploratory deviation"
        )

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

    try:
        for model in models:
            generate(
                target_cfg, model, args.out, max_tokens, target_temperature,
                rate_limit, retries, retry_delay, records_by_id,
                protocol_manifest_sha256=(manifest_digest(manifest) if manifest else None),
                reasoning_effort=target_reasoning_effort,
                system_prompt=target_system_prompt,
            )
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Corpus generation failed: {exc}")

    operational_errors = sum(
        bool(row.get("error")) for row in records_by_id.values()
        if isinstance(row, dict)
    )
    if args.fail_on_error and operational_errors:
        print(f"ERROR: {operational_errors} target call(s) recorded an operational error")
        raise SystemExit(3)
    print(f"\nDone. Corpus at {args.out}. Next: python -m research.run_judges")


if __name__ == "__main__":
    main()
