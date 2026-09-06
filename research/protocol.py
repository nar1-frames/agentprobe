"""Load and validate the machine-readable empirical study protocol."""

import json
import hashlib
import math
import os
import re
import random


DEFAULT_MANIFEST_PATH = os.path.join(os.path.dirname(__file__), "study_manifest.json")


def attack_library_digest(attack_library):
    """Return the canonical digest used to freeze the attack corpus."""

    canonical = json.dumps(
        attack_library, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_manifest(path=DEFAULT_MANIFEST_PATH):
    """Return a validated protocol manifest without mutating the file data."""

    with open(path, encoding="utf-8") as f:
        manifest = json.load(f)
    if not isinstance(manifest, dict):
        raise ValueError("study manifest must be a JSON object")
    corpus = manifest.get("corpus")
    judges = manifest.get("judges")
    labels = manifest.get("labels")
    analysis = manifest.get("analysis")
    if (not isinstance(corpus, dict) or not isinstance(judges, list)
            or not isinstance(labels, dict) or not isinstance(analysis, dict)):
        raise ValueError("study manifest requires corpus, judges, analysis, and labels objects")
    attack_digest = manifest.get("attack_library_sha256")
    if not isinstance(attack_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", attack_digest):
        raise ValueError("manifest attack_library_sha256 must be a 64-character SHA-256 hex digest")
    judge_prompt_version = manifest.get("judge_prompt_version")
    if not isinstance(judge_prompt_version, str) or not judge_prompt_version.strip():
        raise ValueError("manifest judge_prompt_version must be a non-empty string")
    judge_prompt_digest = manifest.get("judge_prompt_sha256")
    if (not isinstance(judge_prompt_digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", judge_prompt_digest)):
        raise ValueError(
            "manifest judge_prompt_sha256 must be a 64-character SHA-256 hex digest"
        )
    targets = corpus.get("target_models")
    responses_per_target = corpus.get("responses_per_target")
    if not isinstance(targets, list) or not targets or not all(
        isinstance(model, str) and model.strip() for model in targets
    ):
        raise ValueError("manifest corpus.target_models must be a non-empty string list")
    if len(set(targets)) != len(targets):
        raise ValueError("manifest corpus.target_models must be unique")
    if isinstance(responses_per_target, bool) or not isinstance(responses_per_target, int) or responses_per_target < 1:
        raise ValueError("manifest corpus.responses_per_target must be a positive integer")
    target_temperature = corpus.get("target_temperature")
    try:
        target_temperature = float(target_temperature)
    except (TypeError, ValueError):
        raise ValueError("manifest corpus.target_temperature must be numeric")
    if not math.isfinite(target_temperature) or not 0 <= target_temperature <= 2:
        raise ValueError("manifest corpus.target_temperature must be between 0 and 2")
    target_max_tokens = corpus.get("target_max_tokens")
    if (isinstance(target_max_tokens, bool) or not isinstance(target_max_tokens, int)
            or not 1 <= target_max_tokens <= 131072):
        raise ValueError(
            "manifest corpus.target_max_tokens must be an integer between 1 and 131072"
        )

    normalized_judges = []
    seen = set()
    for index, judge in enumerate(judges, start=1):
        if not isinstance(judge, dict):
            raise ValueError(f"manifest judge {index} must be an object")
        model = judge.get("model")
        temperature = judge.get("temperature")
        if not isinstance(model, str) or not model.strip():
            raise ValueError(f"manifest judge {index}.model must be a non-empty string")
        try:
            temperature = float(temperature)
        except (TypeError, ValueError):
            raise ValueError(f"manifest judge {index}.temperature must be numeric")
        if not math.isfinite(temperature) or not 0 <= temperature <= 2:
            raise ValueError(f"manifest judge {index}.temperature must be between 0 and 2")
        key = (model, temperature)
        if key in seen:
            raise ValueError(f"manifest contains duplicate judge condition {model}@{temperature:g}")
        seen.add(key)
        normalized_judges.append({"model": model, "temperature": temperature})
    if not normalized_judges:
        raise ValueError("manifest judges must not be empty")

    normalized_analysis = {}
    for role in ("reference", "weak"):
        selection = analysis.get(role)
        if not isinstance(selection, dict):
            raise ValueError(f"manifest analysis.{role} must be an object")
        model = selection.get("model")
        try:
            temperature = float(selection.get("temperature"))
        except (TypeError, ValueError):
            raise ValueError(f"manifest analysis.{role}.temperature must be numeric")
        if not isinstance(model, str) or not model.strip() or not math.isfinite(temperature):
            raise ValueError(f"manifest analysis.{role} requires a model and finite temperature")
        if (model, temperature) not in seen:
            raise ValueError(
                f"manifest analysis.{role} must select a listed judge condition"
            )
        normalized_analysis[role] = {"model": model.strip(), "temperature": temperature}

    repeats = manifest.get("repeats")
    if isinstance(repeats, bool) or not isinstance(repeats, int) or repeats < 2:
        raise ValueError("manifest repeats must be an integer >= 2")
    primary = labels.get("primary")
    second = labels.get("second")
    if not isinstance(primary, str) or not primary.strip():
        raise ValueError("manifest labels.primary must be a non-empty string")
    if not isinstance(second, str) or not second.strip() or second == primary:
        raise ValueError("manifest labels.second must be a distinct non-empty string")
    overlap = labels.get("second_overlap_fraction")
    try:
        overlap = float(overlap)
    except (TypeError, ValueError):
        raise ValueError("manifest labels.second_overlap_fraction must be numeric")
    if not math.isfinite(overlap) or not 0 < overlap <= 1:
        raise ValueError("manifest labels.second_overlap_fraction must be between 0 and 1")
    seed = labels.get("second_subset_seed")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("manifest labels.second_subset_seed must be an integer")
    vocabulary = labels.get("vocabulary")
    if vocabulary != ["COMPLIED", "PARTIAL", "REFUSED"]:
        raise ValueError("manifest labels.vocabulary must be COMPLIED, PARTIAL, REFUSED")

    return {
        **manifest,
        "corpus": {
            **corpus,
            "target_models": list(targets),
            "responses_per_target": responses_per_target,
            "target_temperature": target_temperature,
            "target_max_tokens": target_max_tokens,
        },
        "judges": normalized_judges,
        "judge_prompt_version": judge_prompt_version.strip(),
        "judge_prompt_sha256": judge_prompt_digest,
        "analysis": normalized_analysis,
        "repeats": repeats,
        "labels": {
            **labels,
            "primary": primary.strip(),
            "second": second.strip(),
            "second_overlap_fraction": overlap,
            "second_subset_seed": seed,
            "vocabulary": list(vocabulary),
        },
    }


def expected_configs(manifest):
    """Return the manifest judge matrix in publication-gate CLI form."""

    return [f"{judge['model']}@{judge['temperature']:g}" for judge in manifest["judges"]]


def expected_second_label_ids(corpus, fraction, seed):
    """Return the deterministic response-id subset assigned to labeler two."""

    rows = sorted(
        (row for row in corpus if isinstance(row, dict)
         and isinstance(row.get("response_id"), str)),
        key=lambda row: row["response_id"],
    )
    if not rows:
        return set()
    count = max(1, int(round(len(rows) * float(fraction))))
    sampled = random.Random(seed).sample(rows, count)
    return {
        row["response_id"] for row in sampled
    }


def manifest_digest(manifest):
    """Return a stable digest for the protocol used to produce an analysis."""

    canonical = json.dumps(manifest, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
