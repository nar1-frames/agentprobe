"""Validate corpus, judge, and human-label artifacts before analysis.

The research pipeline is intentionally file-based so every judgment can be
audited. This small gate catches the failures that are hardest to notice in a
paper table: duplicate keys, orphaned judgments, malformed verdicts, and
labels that no longer refer to the frozen corpus.
"""

import argparse
import csv
import math
import os
import re
from collections import Counter

from research._common import canonical_digest, read_jsonl, response_id
from attacks.library import ATTACK_LIBRARY


VALID_INTERNAL_VERDICTS = {"VULNERABLE", "PARTIAL", "SAFE", "SUSPICIOUS"}
VALID_HUMAN_LABELS = {"COMPLIED", "PARTIAL", "REFUSED"}


def _integer(value, name, minimum=0):
    if isinstance(value, bool):
        raise ValueError(f"{name} is not an integer")
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} is not an integer")
    if not math.isfinite(number) or number != int(number) or int(number) < minimum:
        raise ValueError(f"{name} is not a valid integer")
    return int(number)


def _duplicate_keys(rows, key_fn):
    counts = Counter(key_fn(row) for row in rows)
    return [key for key, count in counts.items() if count > 1]


def validate_corpus(corpus, attack_library=None):
    errors = []
    warnings = []
    ids = set()
    missing_temperature_rows = 0
    for index, row in enumerate(corpus, start=1):
        if not isinstance(row, dict):
            errors.append(f"corpus row {index}: expected a JSON object")
            continue
        required = {"response_id", "category", "attack_index", "target_model", "response"}
        missing = sorted(required - row.keys())
        if missing:
            errors.append(f"corpus row {index}: missing {', '.join(missing)}")
            continue
        rid = row["response_id"]
        if not isinstance(rid, str) or not rid.strip():
            errors.append(f"corpus row {index}: response_id must be a non-empty string")
            continue
        if not isinstance(row["category"], str) or not row["category"].strip():
            errors.append(f"corpus row {index}: category must be a non-empty string")
            continue
        if not isinstance(row["target_model"], str) or not row["target_model"].strip():
            errors.append(f"corpus row {index}: target_model must be a non-empty string")
            continue
        if rid in ids:
            errors.append(f"corpus row {index}: duplicate response_id {rid}")
        ids.add(rid)
        try:
            attack_index = _integer(row["attack_index"], "attack_index")
            expected = response_id(row["category"], attack_index, row["target_model"])
        except (TypeError, ValueError):
            errors.append(f"corpus row {index}: attack_index is not an integer")
            continue
        if rid != expected:
            errors.append(f"corpus row {index}: response_id does not match its stable key")
        if "target_temperature" not in row:
            missing_temperature_rows += 1
        else:
            try:
                target_temperature = float(row["target_temperature"])
            except (TypeError, ValueError):
                errors.append(f"corpus row {index}: target_temperature is not numeric")
            else:
                if (isinstance(row["target_temperature"], bool)
                        or not math.isfinite(target_temperature)
                        or not 0 <= target_temperature <= 2):
                    errors.append(
                        f"corpus row {index}: target_temperature must be between 0 and 2"
                    )
        if "max_tokens" in row:
            try:
                _integer(row["max_tokens"], "max_tokens", minimum=1)
            except (TypeError, ValueError):
                errors.append(f"corpus row {index}: max_tokens is not a positive integer")
        if attack_library is not None:
            attacks = attack_library.get(row["category"], [])
            if attack_index < 0 or attack_index >= len(attacks):
                errors.append(f"corpus row {index}: attack index is outside the attack library")
            else:
                attack = attacks[attack_index]
                if row.get("attack_prompt") != attack.get("prompt"):
                    errors.append(f"corpus row {index}: attack prompt differs from library")
                if row.get("severity") != attack.get("severity"):
                    errors.append(f"corpus row {index}: severity differs from library")
        if row.get("error"):
            warnings.append(f"corpus row {index}: target error is excluded from model metrics")
    if missing_temperature_rows:
        warnings.append(
            f"{missing_temperature_rows} corpus rows lack target_temperature metadata; "
            "publication gate will require regeneration"
        )
    return {"errors": errors, "warnings": warnings, "ids": ids}


def validate_judgements(judgements, corpus_ids, corpus_by_id=None, corpus_sha256=None):
    errors = []
    warnings = []
    valid = 0
    operational_errors = 0
    missing_prompt_metadata = 0
    missing_corpus_provenance = 0
    keys = set()
    for index, row in enumerate(judgements, start=1):
        if not isinstance(row, dict):
            errors.append(f"judgement row {index}: expected a JSON object")
            continue
        required = {"response_id", "judge_model", "temperature", "run_idx", "verdict"}
        missing = sorted(required - row.keys())
        if missing:
            errors.append(f"judgement row {index}: missing {', '.join(missing)}")
            continue
        rid = row["response_id"]
        model = row["judge_model"]
        if not isinstance(rid, str) or not rid.strip():
            errors.append(f"judgement row {index}: response_id must be a non-empty string")
            continue
        if not isinstance(model, str) or not model.strip():
            errors.append(f"judgement row {index}: judge_model must be a non-empty string")
            continue
        if rid not in corpus_ids:
            errors.append(f"judgement row {index}: orphan response_id {rid}")
        elif corpus_by_id and row.get("target_model") not in (None, corpus_by_id[rid].get("target_model")):
            errors.append(f"judgement row {index}: target_model disagrees with corpus")
        try:
            temp = float(row["temperature"])
            run_idx = _integer(row["run_idx"], "run_idx")
        except (TypeError, ValueError):
            errors.append(f"judgement row {index}: temperature/run_idx is not numeric")
            continue
        if not math.isfinite(temp):
            errors.append(f"judgement row {index}: temperature is not finite")
            continue
        if "judge_prompt_version" not in row or "judge_prompt_sha256" not in row:
            missing_prompt_metadata += 1
        else:
            if (not isinstance(row["judge_prompt_version"], str)
                    or not row["judge_prompt_version"].strip()):
                errors.append(f"judgement row {index}: judge_prompt_version is empty")
            if (not isinstance(row["judge_prompt_sha256"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", row["judge_prompt_sha256"])):
                errors.append(f"judgement row {index}: judge_prompt_sha256 is invalid")
        row_digest = row.get("corpus_sha256")
        if row_digest is None:
            missing_corpus_provenance += 1
        elif (not isinstance(row_digest, str)
              or not re.fullmatch(r"[0-9a-f]{64}", row_digest)):
            errors.append(f"judgement row {index}: corpus_sha256 is invalid")
        elif corpus_sha256 is not None and row_digest != corpus_sha256:
            errors.append(f"judgement row {index}: corpus_sha256 does not match corpus")
        if not 0 <= temp <= 2:
            errors.append(f"judgement row {index}: temperature must be between 0 and 2")
            continue
        key = (rid, model, temp, run_idx)
        if key in keys:
            errors.append(f"judgement row {index}: duplicate key {key}")
        keys.add(key)
        if row.get("error"):
            operational_errors += 1
            continue
        if row["verdict"] not in VALID_INTERNAL_VERDICTS:
            errors.append(f"judgement row {index}: invalid verdict {row['verdict']!r}")
        else:
            valid += 1
    if operational_errors:
        warnings.append(f"{operational_errors} operational judge errors are excluded from metrics")
    if missing_prompt_metadata:
        warnings.append(
            f"{missing_prompt_metadata} judge rows lack prompt provenance metadata; "
            "publication gate will require regeneration"
        )
    if missing_corpus_provenance:
        warnings.append(
            f"{missing_corpus_provenance} judge rows lack corpus provenance metadata; "
            "publication gate will require regeneration"
        )
    return {
        "errors": errors,
        "warnings": warnings,
        "valid_judgements": valid,
        "operational_errors": operational_errors,
        "keys": keys,
    }


def validate_labels(labels, corpus_ids, corpus_sha256=None):
    errors = []
    keys = set()
    missing_corpus_provenance = 0
    for index, row in enumerate(labels, start=1):
        if not isinstance(row, dict):
            errors.append(f"label row {index}: expected a mapping")
            continue
        required = {"response_id", "labeler", "label"}
        missing = sorted(required - row.keys())
        if missing:
            errors.append(f"label row {index}: missing {', '.join(missing)}")
            continue
        if not isinstance(row["response_id"], str) or not row["response_id"].strip():
            errors.append(f"label row {index}: response_id must be a non-empty string")
            continue
        if not isinstance(row["labeler"], str) or not row["labeler"].strip():
            errors.append(f"label row {index}: labeler is empty")
            continue
        key = (row["response_id"], row["labeler"])
        if key in keys:
            errors.append(f"label row {index}: duplicate key {key}")
        keys.add(key)
        if row["response_id"] not in corpus_ids:
            errors.append(f"label row {index}: orphan response_id {row['response_id']}")
        if not isinstance(row["label"], str) or row["label"] not in VALID_HUMAN_LABELS:
            errors.append(f"label row {index}: invalid label {row['label']!r}")
        row_digest = row.get("corpus_sha256")
        if row_digest is None:
            missing_corpus_provenance += 1
        elif (not isinstance(row_digest, str)
              or not re.fullmatch(r"[0-9a-f]{64}", row_digest)):
            errors.append(f"label row {index}: corpus_sha256 is invalid")
        elif corpus_sha256 is not None and row_digest != corpus_sha256:
            errors.append(f"label row {index}: corpus_sha256 does not match corpus")
    warnings = []
    if missing_corpus_provenance:
        warnings.append(
            f"{missing_corpus_provenance} label rows lack corpus provenance metadata; "
            "publication gate will require relabeling"
        )
    return {"errors": errors, "warnings": warnings, "labels": len(labels)}


def validate_dataset(corpus, judgements=None, labels=None, attack_library=None):
    """Return a JSON-friendly validation report; never mutates input data."""

    corpus = list(corpus or [])
    judgements = list(judgements or [])
    labels = list(labels or [])
    corpus_report = validate_corpus(corpus, attack_library)
    corpus_sha256 = canonical_digest(corpus)
    corpus_by_id = {
        row.get("response_id"): row for row in corpus
        if isinstance(row, dict) and isinstance(row.get("response_id"), str)
    }
    judgement_report = validate_judgements(
        judgements, corpus_report["ids"], corpus_by_id, corpus_sha256
    )
    label_report = validate_labels(labels, corpus_report["ids"], corpus_sha256)
    errors = corpus_report["errors"] + judgement_report["errors"] + label_report["errors"]
    warnings = corpus_report["warnings"] + judgement_report["warnings"] + label_report["warnings"]
    return {
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "corpus_rows": len(corpus),
        "judgement_rows": len(judgements),
        "valid_judgements": judgement_report["valid_judgements"],
        "operational_judge_errors": judgement_report["operational_errors"],
        "label_rows": len(labels),
        "corpus_sha256": canonical_digest(corpus),
    }


def _read_labels(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def main():
    ap = argparse.ArgumentParser(description="Validate research artifacts before analysis.")
    ap.add_argument("--corpus", default="data/corpus.jsonl")
    ap.add_argument("--judgements", default="data/judgements.jsonl")
    ap.add_argument("--labels", default="data/labels.csv")
    args = ap.parse_args()
    corpus = read_jsonl(args.corpus) if os.path.exists(args.corpus) else []
    judgements = read_jsonl(args.judgements) if os.path.exists(args.judgements) else []
    labels = _read_labels(args.labels)
    report = validate_dataset(corpus, judgements, labels, ATTACK_LIBRARY)
    print(f"corpus={report['corpus_rows']} judgements={report['judgement_rows']} "
          f"labels={report['label_rows']} operational_errors={report['operational_judge_errors']} "
          f"corpus_sha256={report['corpus_sha256']}")
    for warning in report["warnings"]:
        print(f"WARNING: {warning}")
    for error in report["errors"]:
        print(f"ERROR: {error}")
    print("VALID" if report["valid"] else "INVALID")
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
