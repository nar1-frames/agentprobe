"""Publication-readiness checks for the empirical judge study."""

import argparse
import csv
import json
import math
import os
import re
from collections import defaultdict

from attacks.library import ATTACK_LIBRARY
from research._common import (
    canonical_digest, load_config, provider_config_digest, read_jsonl,
)
from research.protocol import (
    DEFAULT_MANIFEST_PATH,
    attack_library_digest,
    expected_configs,
    expected_second_label_ids,
    load_manifest,
    manifest_digest,
)
from research.validate import (
    VALID_HUMAN_LABELS,
    VALID_INTERNAL_VERDICTS,
    validate_dataset,
)


def _run_index(value):
    if isinstance(value, bool):
        raise ValueError("run_idx must be a non-negative integer")
    number = float(value)
    if not math.isfinite(number) or number != int(number) or int(number) < 0:
        raise ValueError("run_idx must be a non-negative integer")
    return int(number)


def _normalize_configs(configs):
    normalized = []
    for config in configs or ():
        if isinstance(config, str):
            try:
                model, temperature = config.rsplit("@", 1)
                config = (model, float(temperature))
            except (ValueError, TypeError):
                raise ValueError(
                    f"expected judge config must be MODEL@TEMP, got {config!r}"
                )
        if len(config) != 2:
            raise ValueError(f"expected judge config must contain model and temperature: {config!r}")
        model = str(config[0]).strip()
        temperature = float(config[1])
        if not model or not math.isfinite(temperature):
            raise ValueError(f"expected judge config must contain a model and finite temperature: {config!r}")
        normalized.append((model, temperature))
    return tuple(normalized)


def check_readiness(corpus, judgements, labels, primary="ren", second=None,
                    expected_k=5, expected_configs=None,
                    expected_target_models=None, expected_corpus_rows=None,
                    expected_attack_library_sha256=None,
                    expected_judge_prompt_version=None,
                    expected_judge_prompt_sha256=None,
                    expected_target_temperature=None,
                    expected_target_max_tokens=None,
                    expected_second_overlap_fraction=None,
                    expected_second_subset_seed=None,
                    expected_target_provider=None,
                    expected_judge_provider=None,
                    expected_judge_max_tokens=None,
                    expected_protocol_manifest_sha256=None,
                    expected_labeling_guide_sha256=None,
                    expected_target_config_sha256=None,
                    expected_judge_config_sha256=None,
                    expected_target_reasoning_effort=None,
                    expected_target_system_prompt=None,
                    expected_judge_reasoning_effort=None):
    """Return explicit blocking reasons; do not silently grade incomplete data."""

    if not isinstance(expected_k, int) or isinstance(expected_k, bool) or expected_k < 1:
        raise ValueError("expected_k must be a positive integer")

    blocking = []
    corpus = list(corpus or [])
    judgements = list(judgements or [])
    labels = list(labels or [])
    corpus_sha256 = canonical_digest(corpus)
    corpus_ids = set()
    for index, row in enumerate(corpus, start=1):
        if not isinstance(row, dict) or not isinstance(row.get("response_id"), str) or not row["response_id"].strip():
            blocking.append(f"corpus row {index} is missing a non-empty response_id")
            continue
        corpus_ids.add(row["response_id"])
    if len(corpus_ids) != len(corpus):
        blocking.append("corpus contains duplicate or malformed response_id rows")
    if not corpus_ids:
        blocking.append("corpus is empty")
    if expected_corpus_rows is not None and len(corpus) != expected_corpus_rows:
        blocking.append(
            f"corpus contains {len(corpus)} rows; manifest requires {expected_corpus_rows}"
        )
    if expected_target_models is not None:
        observed_targets = {
            row.get("target_model") for row in corpus
            if isinstance(row, dict) and isinstance(row.get("target_model"), str)
        }
        expected_targets = set(expected_target_models)
        if observed_targets != expected_targets:
            blocking.append(
                f"corpus target models {sorted(observed_targets, key=str)} do not match "
                f"manifest {sorted(expected_targets)}"
            )
    if expected_target_provider is not None:
        observed_providers = {
            row.get("target_provider") for row in corpus
            if isinstance(row, dict) and isinstance(row.get("target_provider"), str)
        }
        if observed_providers != {expected_target_provider}:
            blocking.append(
                "corpus target provider metadata does not match the manifest "
                f"(observed {sorted(observed_providers, key=str)!r}, expected "
                f"{expected_target_provider!r})"
            )
    if expected_target_reasoning_effort is not None:
        observed_efforts = [
            row.get("target_reasoning_effort") if isinstance(row, dict) else None
            for row in corpus
        ]
        if len(observed_efforts) != len(corpus) or any(
                effort != expected_target_reasoning_effort for effort in observed_efforts):
            blocking.append(
                "corpus target_reasoning_effort metadata does not match the study manifest"
            )
    if expected_target_system_prompt is not None:
        observed_prompts = [
            row.get("target_system_prompt") if isinstance(row, dict) else None
            for row in corpus
        ]
        if len(observed_prompts) != len(corpus) or any(
                prompt != expected_target_system_prompt for prompt in observed_prompts):
            blocking.append(
                "corpus target_system_prompt metadata does not match the study manifest"
            )
    if expected_target_temperature is not None:
        raw_temperatures = [
            row.get("target_temperature") if isinstance(row, dict) else None
            for row in corpus
        ]
        try:
            observed_temperatures = [float(value) for value in raw_temperatures]
        except (TypeError, ValueError):
            observed_temperatures = []
        if (len(observed_temperatures) != len(corpus)
                or any(
                    temperature != float(expected_target_temperature)
                    for temperature in observed_temperatures
                )):
            blocking.append(
                "corpus target_temperature metadata does not match the manifest "
                f"({len(observed_temperatures)}/{len(corpus)} rows present, expected "
                f"{float(expected_target_temperature):g})"
            )
    if expected_target_max_tokens is not None:
        observed_max_tokens = [
            row.get("max_tokens") if isinstance(row, dict) else None
            for row in corpus
        ]
        if (len(observed_max_tokens) != len(corpus)
                or any(value != expected_target_max_tokens for value in observed_max_tokens)):
            blocking.append(
                "corpus max_tokens metadata does not match the manifest "
                f"({observed_max_tokens!r} observed, "
                f"expected {expected_target_max_tokens})"
            )
    if expected_protocol_manifest_sha256 is not None:
        corpus_protocols = [
            row.get("protocol_manifest_sha256") if isinstance(row, dict) else None
            for row in corpus
        ]
        if (len(corpus_protocols) != len(corpus)
                or any(value != expected_protocol_manifest_sha256 for value in corpus_protocols)):
            blocking.append(
                "corpus protocol manifest metadata does not match the study manifest"
            )
        target_config_digests = [
            row.get("target_config_sha256") if isinstance(row, dict) else None
            for row in corpus
        ]
        valid_target_config_digests = (
            len(target_config_digests) == len(corpus)
            and all(
                isinstance(digest, str)
                and re.fullmatch(r"[0-9a-f]{64}", digest)
                for digest in target_config_digests
            )
        )
        if not valid_target_config_digests:
            blocking.append(
                "corpus target provider configuration provenance is missing or invalid"
            )
        if expected_target_config_sha256 is not None and valid_target_config_digests:
            expected_target_configs = (
                {expected_target_config_sha256}
                if isinstance(expected_target_config_sha256, str)
                else set(expected_target_config_sha256)
            )
            if set(target_config_digests) != expected_target_configs:
                blocking.append(
                    "corpus target provider configuration provenance does not match "
                    "the configured study target"
                )
    if expected_attack_library_sha256 is not None:
        actual_attack_digest = attack_library_digest(ATTACK_LIBRARY)
        if actual_attack_digest != expected_attack_library_sha256:
            blocking.append("attack library does not match the study manifest digest")

        # The executable gate must enforce the same row-level integrity rules
        # as the standalone validator. Counts, stable IDs, and corpus digests
        # alone do not prove that a row still refers to the preregistered
        # attack prompt and severity. Keep this conditional for the library
        # API's small synthetic fixtures; the manifest-backed CLI always
        # supplies the attack-library digest and therefore gets fail-closed
        # artifact validation.
        integrity = validate_dataset(
            corpus, judgements, labels, ATTACK_LIBRARY,
            expected_labeling_guide_sha256=expected_labeling_guide_sha256,
        )
        for error in integrity["errors"]:
            blocking.append(f"dataset integrity: {error}")
    if expected_judge_prompt_version is not None or expected_judge_prompt_sha256 is not None:
        prompt_versions = [
            row.get("judge_prompt_version") for row in judgements
            if isinstance(row, dict)
        ]
        prompt_digests = [
            row.get("judge_prompt_sha256") for row in judgements
            if isinstance(row, dict)
        ]
        if (expected_judge_prompt_version is not None
                and (len(prompt_versions) != len(judgements)
                     or any(value != expected_judge_prompt_version for value in prompt_versions))):
            blocking.append(
                "judge prompt version metadata does not match the study manifest "
                f"(expected {expected_judge_prompt_version})"
            )
        if (expected_judge_prompt_sha256 is not None
                and (len(prompt_digests) != len(judgements)
                     or any(value != expected_judge_prompt_sha256 for value in prompt_digests))):
            blocking.append(
                "judge prompt digest metadata does not match the study manifest"
            )
    if expected_judge_reasoning_effort is not None:
        observed_efforts = [
            row.get("judge_reasoning_effort") if isinstance(row, dict) else None
            for row in judgements
        ]
        if len(observed_efforts) != len(judgements) or any(
                effort != expected_judge_reasoning_effort for effort in observed_efforts):
            blocking.append(
                "judge reasoning_effort metadata does not match the study manifest"
            )
    if expected_judge_provider is not None:
        judge_providers = [
            row.get("judge_provider") if isinstance(row, dict) else None
            for row in judgements
        ]
        if (len(judge_providers) != len(judgements)
                or any(value != expected_judge_provider for value in judge_providers)):
            blocking.append("judge provider metadata does not match the study manifest")
    if expected_judge_max_tokens is not None:
        judge_token_budgets = [
            row.get("judge_max_tokens") if isinstance(row, dict) else None
            for row in judgements
        ]
        if (len(judge_token_budgets) != len(judgements)
                or any(value != expected_judge_max_tokens for value in judge_token_budgets)):
            blocking.append("judge max_tokens metadata does not match the study manifest")
    if expected_protocol_manifest_sha256 is not None:
        judge_protocols = [
            row.get("protocol_manifest_sha256") if isinstance(row, dict) else None
            for row in judgements
        ]
        if (len(judge_protocols) != len(judgements)
                or any(value != expected_protocol_manifest_sha256 for value in judge_protocols)):
            blocking.append(
                "judge protocol manifest metadata does not match the study manifest"
            )
        judge_config_digests = [
            row.get("judge_config_sha256") if isinstance(row, dict) else None
            for row in judgements
        ]
        if (len(judge_config_digests) != len(judgements)
                or not all(
                    isinstance(digest, str)
                    and re.fullmatch(r"[0-9a-f]{64}", digest)
                    for digest in judge_config_digests
                )):
            blocking.append("judge configuration provenance is missing or invalid")

    if expected_judge_config_sha256 is not None:
        mismatched_judge_configs = []
        for row in judgements:
            if not isinstance(row, dict):
                continue
            model = row.get("judge_model")
            if not isinstance(model, str):
                continue
            try:
                key = (model, float(row.get("temperature")))
            except (TypeError, ValueError):
                continue
            expected_digest = expected_judge_config_sha256.get(key)
            if expected_digest is not None and row.get("judge_config_sha256") != expected_digest:
                mismatched_judge_configs.append(key)
        if mismatched_judge_configs:
            blocking.append(
                "judge provider configuration provenance does not match the configured "
                "study judge"
            )

    if judgements:
        judge_digests = [
            row.get("corpus_sha256") for row in judgements
            if isinstance(row, dict)
        ]
        if (len(judge_digests) != len(judgements)
                or not all(digest == corpus_sha256 for digest in judge_digests)):
            blocking.append(
                "judge evidence is not bound to the current corpus digest"
            )
    if labels:
        label_digests = [
            row.get("corpus_sha256") for row in labels
            if isinstance(row, dict)
        ]
        if (len(label_digests) != len(labels)
                or not all(digest == corpus_sha256 for digest in label_digests)):
            blocking.append(
                "human labels are not bound to the current corpus digest"
            )
    if expected_labeling_guide_sha256 is not None:
        guide_digests = [
            row.get("labeling_guide_sha256") if isinstance(row, dict) else None
            for row in labels
        ]
        if (len(guide_digests) != len(labels)
                or any(value != expected_labeling_guide_sha256 for value in guide_digests)):
            blocking.append(
                "human labels are missing or bound to a different labeling guide"
            )

    primary_rows = [row for row in labels
                    if isinstance(row, dict) and row.get("labeler") == primary]
    primary_ids = {
        row.get("response_id") for row in primary_rows
        if isinstance(row.get("response_id"), str)
    }
    target_errors = sum(
        1 for row in corpus if isinstance(row, dict) and row.get("error")
    )
    if target_errors:
        blocking.append(f"{target_errors} target API errors remain in the corpus")
    if primary_ids != corpus_ids:
        blocking.append(
            f"primary labels cover {len(primary_ids)}/{len(corpus_ids)} corpus responses"
        )
    if len(primary_rows) != len(primary_ids):
        blocking.append(f"primary label set contains duplicate response rows ({len(primary_rows)} rows)")

    required_label_fields = {"response_id", "labeler", "label"}
    for index, row in enumerate(labels, start=1):
        if not isinstance(row, dict):
            blocking.append(f"label row {index} is not an object")
            continue
        missing = sorted(required_label_fields - row.keys())
        if missing:
            blocking.append(f"label row {index} is missing {', '.join(missing)}")
    label_keys = []
    for row in labels:
        if not isinstance(row, dict):
            continue
        response_id = row.get("response_id")
        labeler = row.get("labeler")
        if isinstance(response_id, str) and isinstance(labeler, str):
            label_keys.append((response_id, labeler))
    if len(label_keys) != len(set(label_keys)):
        blocking.append("label set contains duplicate response_id/labeler keys")
    invalid_labels = [
        row.get("label") for row in labels
        if isinstance(row, dict)
        and (not isinstance(row.get("label"), str)
             or row.get("label") not in VALID_HUMAN_LABELS)
    ]
    if invalid_labels:
        blocking.append(
            f"label set contains invalid labels: {sorted({repr(label) for label in invalid_labels})}"
        )
    orphan_labels = [row.get("response_id") for row in labels if isinstance(row, dict)
                     if row.get("response_id") not in corpus_ids]
    if orphan_labels:
        blocking.append(f"label set contains {len(orphan_labels)} orphan response rows")

    if not second:
        blocking.append("an independent second labeler has not been specified")
    else:
        second_ids = {
            row.get("response_id") for row in labels
            if isinstance(row, dict)
            and row.get("labeler") == second
            and isinstance(row.get("response_id"), str)
        }
        overlap = primary_ids & second_ids
        if expected_second_overlap_fraction is not None and expected_second_subset_seed is not None:
            expected_ids = expected_second_label_ids(
                corpus, expected_second_overlap_fraction, expected_second_subset_seed
            )
            if second_ids != expected_ids:
                blocking.append(
                    f"second-label subset does not match the manifest assignment "
                    f"({len(second_ids)} observed, {len(expected_ids)} expected)"
                )
        elif not overlap:
            blocking.append(f"labelers '{primary}' and '{second}' have no overlapping responses")
        elif len(overlap) < max(1, round(len(corpus_ids) * 0.3)):
            blocking.append(
                f"independent-label overlap is {len(overlap)} responses; "
                f"at least {max(1, round(len(corpus_ids) * 0.3))} are required"
            )

    configs = defaultdict(lambda: defaultdict(list))
    operational_errors = 0
    judgement_keys = []
    required_judgement_fields = {
        "response_id", "judge_model", "temperature", "run_idx", "verdict"
    }
    for index, row in enumerate(judgements, start=1):
        if not isinstance(row, dict):
            blocking.append(f"judge row {index} is not an object")
            continue
        missing = sorted(required_judgement_fields - row.keys())
        if missing:
            blocking.append(f"judge row {index} is missing {', '.join(missing)}")
            continue
        rid = row.get("response_id")
        model = row.get("judge_model")
        if not isinstance(rid, str) or not rid.strip() or not isinstance(model, str) or not model.strip():
            blocking.append(f"judge row {index} has an empty response_id or judge_model")
            continue
        try:
            temp = float(row.get("temperature", 0.0))
        except (TypeError, ValueError):
            blocking.append(f"judge row has invalid temperature: {row.get('temperature')!r}")
            continue
        if not math.isfinite(temp):
            blocking.append(f"judge row has non-finite temperature: {row.get('temperature')!r}")
            continue
        try:
            run_idx = _run_index(row.get("run_idx"))
        except (TypeError, ValueError):
            blocking.append(f"judge row has invalid run_idx: {row.get('run_idx')!r}")
            continue
        judgement_keys.append((rid, model, temp, run_idx))
        if rid not in corpus_ids:
            blocking.append(f"judge set contains orphan response_id {rid}")
        verdict = row.get("verdict")
        if not row.get("error") and (
            not isinstance(verdict, str) or verdict not in VALID_INTERNAL_VERDICTS
        ):
            blocking.append(f"judge set contains invalid verdict {row.get('verdict')!r}")
        key = (model, temp)
        if row.get("error"):
            operational_errors += 1
            continue
        configs[key][row["response_id"]].append(row)
    if len(judgement_keys) != len(set(judgement_keys)):
        blocking.append("judge set contains duplicate response_id/judge/temperature/run keys")
    if operational_errors:
        blocking.append(f"{operational_errors} operational judge errors remain")
    observed_configs = set(configs)
    required_configs = set(_normalize_configs(expected_configs)) or observed_configs
    unexpected_configs = observed_configs - required_configs if expected_configs else set()
    if unexpected_configs:
        rendered = ", ".join(
            f"{model}@{temp:g}" for model, temp in sorted(unexpected_configs)
        )
        blocking.append(f"unexpected judge configurations present: {rendered}")
    for (model, temp) in sorted(required_configs | observed_configs):
        by_response = configs.get((model, temp), {})
        if (model, temp) not in observed_configs:
            blocking.append(f"missing judge configuration {model}@{temp}")
        counts = {rid: len(rows) for rid, rows in by_response.items()}
        missing = len(corpus_ids - set(counts))
        complete = sum(1 for rid in corpus_ids if counts.get(rid, 0) == expected_k)
        incomplete = len(corpus_ids) - complete
        if missing or incomplete:
            blocking.append(
                f"{model}@{temp}: {complete}/{len(corpus_ids)} items have exactly "
                f"k={expected_k} ({incomplete} incomplete)"
            )
    if not configs:
        blocking.append("no judge configurations are present")

    return {
        "ready": not blocking,
        "blocking_reasons": blocking,
        "corpus_responses": len(corpus_ids),
        "target_errors": target_errors,
        "primary_labels": len(primary_ids),
        "judge_configurations": len(configs),
        "expected_judge_configurations": len(required_configs),
        "expected_k": expected_k,
        "expected_target_models": list(expected_target_models) if expected_target_models is not None else None,
        "expected_corpus_rows": expected_corpus_rows,
        "expected_attack_library_sha256": expected_attack_library_sha256,
        "dataset_integrity_errors": [
            reason for reason in blocking if reason.startswith("dataset integrity:")
        ],
        "expected_judge_prompt_version": expected_judge_prompt_version,
        "expected_judge_prompt_sha256": expected_judge_prompt_sha256,
        "expected_target_temperature": expected_target_temperature,
        "expected_target_max_tokens": expected_target_max_tokens,
        "expected_target_provider": expected_target_provider,
        "expected_judge_provider": expected_judge_provider,
        "expected_judge_max_tokens": expected_judge_max_tokens,
        "expected_protocol_manifest_sha256": expected_protocol_manifest_sha256,
        "expected_labeling_guide_sha256": expected_labeling_guide_sha256,
        "expected_target_config_sha256": expected_target_config_sha256,
        "expected_judge_config_sha256": expected_judge_config_sha256,
        "expected_target_reasoning_effort": expected_target_reasoning_effort,
        "expected_target_system_prompt": expected_target_system_prompt,
        "expected_judge_reasoning_effort": expected_judge_reasoning_effort,
        "corpus_sha256": corpus_sha256,
    }


def _read_labels(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _jsonable(value):
    """Convert diagnostic values to stable JSON without losing key meaning."""

    if isinstance(value, dict):
        return {
            (f"{key[0]}@{key[1]:g}" if isinstance(key, tuple) and len(key) == 2
             else str(key)): _jsonable(item)
            for key, item in value.items()
        }
    if isinstance(value, (set, tuple)):
        return [_jsonable(item) for item in sorted(value, key=str)]
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    return value


def main():
    ap = argparse.ArgumentParser(description="Check whether the study can be published.")
    ap.add_argument("--corpus", default="data/corpus.jsonl")
    ap.add_argument("--judgements", default="data/judgements.jsonl")
    ap.add_argument("--labels", default="data/labels.csv")
    ap.add_argument("--primary", default=None)
    ap.add_argument("--second", default=None)
    ap.add_argument("--k", type=int, default=None)
    ap.add_argument(
        "--manifest", default=DEFAULT_MANIFEST_PATH,
        help="machine-readable study protocol used for default gate requirements",
    )
    ap.add_argument(
        "--config", default="config.yaml",
        help="validated provider config used to verify exact evidence provenance",
    )
    ap.add_argument(
        "--expected-config",
        action="append",
        default=None,
        metavar="MODEL@TEMP",
        help="required judge condition; repeat for every preregistered condition",
    )
    ap.add_argument("--json", default=None)
    args = ap.parse_args()
    corpus = read_jsonl(args.corpus) if os.path.exists(args.corpus) else []
    judgements = read_jsonl(args.judgements) if os.path.exists(args.judgements) else []
    manifest = None
    if args.manifest and os.path.exists(args.manifest):
        try:
            manifest = load_manifest(args.manifest)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            ap.error(f"invalid study manifest: {exc}")
    primary = args.primary or (manifest or {}).get("labels", {}).get("primary", "ren")
    second = args.second
    if second is None and manifest:
        second = manifest["labels"]["second"]
    expected_k = args.k if args.k is not None else (manifest or {}).get("repeats", 5)
    required_configs = args.expected_config
    if required_configs is None and manifest:
        required_configs = expected_configs(manifest)
    expected_targets = (manifest or {}).get("corpus", {}).get("target_models")
    expected_rows = None
    if manifest:
        expected_rows = (
            len(expected_targets) * manifest["corpus"]["responses_per_target"]
        )
    expected_attack_digest = (manifest or {}).get("attack_library_sha256")
    expected_judge_prompt_version = (manifest or {}).get("judge_prompt_version")
    expected_judge_prompt_sha256 = (manifest or {}).get("judge_prompt_sha256")
    expected_target_temperature = (manifest or {}).get("corpus", {}).get("target_temperature")
    expected_target_max_tokens = (manifest or {}).get("corpus", {}).get("target_max_tokens")
    expected_target_provider = (manifest or {}).get("corpus", {}).get("target_provider")
    expected_judge_provider = (manifest or {}).get("judge_provider")
    expected_judge_max_tokens = (manifest or {}).get("judge_max_tokens")
    expected_protocol_manifest_sha256 = manifest_digest(manifest) if manifest else None
    expected_labeling_guide_sha256 = (manifest or {}).get("labeling_guide_sha256")
    expected_target_config_sha256 = None
    expected_judge_config_sha256 = None
    expected_target_reasoning_effort = (manifest or {}).get("target_reasoning_effort")
    expected_target_system_prompt = (manifest or {}).get("corpus", {}).get(
        "target_system_prompt"
    )
    expected_judge_reasoning_effort = (manifest or {}).get("judge_reasoning_effort")
    if manifest:
        try:
            config = load_config(args.config)
            target_config = config["target"]
            expected_target_config_sha256 = {
                provider_config_digest({
                    **target_config,
                    "model": model,
                    "max_tokens": manifest["corpus"]["target_max_tokens"],
                    "temperature": manifest["corpus"]["target_temperature"],
                })
                for model in manifest["corpus"]["target_models"]
            }
            judge_config = config["judge"]
            expected_judge_config_sha256 = {
                (judge["model"], float(judge["temperature"])): provider_config_digest({
                    **judge_config,
                    "model": judge["model"],
                    "temperature": judge["temperature"],
                    "max_tokens": manifest["judge_max_tokens"],
                })
                for judge in manifest["judges"]
            }
        except (OSError, KeyError, TypeError, ValueError) as exc:
            ap.error(f"invalid provider config: {exc}")
    try:
        report = check_readiness(
            corpus, judgements, _read_labels(args.labels), primary, second,
            expected_k, required_configs, expected_targets, expected_rows,
            expected_attack_digest,
            expected_judge_prompt_version, expected_judge_prompt_sha256,
            expected_target_temperature, expected_target_max_tokens,
            (manifest or {}).get("labels", {}).get("second_overlap_fraction"),
            (manifest or {}).get("labels", {}).get("second_subset_seed"),
            expected_target_provider,
            expected_judge_provider,
            expected_judge_max_tokens,
            expected_protocol_manifest_sha256,
            expected_labeling_guide_sha256,
            expected_target_config_sha256,
            expected_judge_config_sha256,
            expected_target_reasoning_effort,
            expected_target_system_prompt,
            expected_judge_reasoning_effort,
        )
    except ValueError as exc:
        ap.error(str(exc))
    if manifest:
        report["protocol_manifest"] = {
            "path": args.manifest,
            "sha256": manifest_digest(manifest),
        }
    print("READY" if report["ready"] else "NOT READY")
    for reason in report["blocking_reasons"]:
        print(f"BLOCKED: {reason}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(_jsonable(report), f, indent=2)
            f.write("\n")
    return 0 if report["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
