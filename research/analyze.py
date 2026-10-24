#!/usr/bin/env python3
# ============================================================
# STEPS D/E — Analysis
# ============================================================
# Joins the three data files and answers the research questions:
#
#   RQ1 (validity):     judge vs human — Cohen's kappa, per-class
#                       precision/recall, 3x3 confusion matrix.
#   RQ2 (reliability):  judge vs itself across k runs — self-agreement
#                       and Fleiss' kappa, per judge config.
#   RQ3 (kw vs judge):  keyword stage vs judge-majority confusion.
#   (inter-annotator):  human primary vs second labeler, if present.
#
# This runs with zero external ML deps (see research/metrics.py). It
# prints a report and, with --json, writes a machine-readable summary
# you can drop figures from.
#
# Usage
# -----
#   python -m research.analyze
#   python -m research.analyze --primary ren --second friend \
#       --reference-judge openai/gpt-oss-120b --reference-temperature 0.0 \
#       --json data/results.json
# ============================================================

import argparse
import csv
import json
import math
import os
from collections import defaultdict, Counter

from attacks.library import ATTACK_LIBRARY
from research._common import canonical_digest, load_config, read_jsonl
from research.protocol import DEFAULT_MANIFEST_PATH, load_manifest, manifest_digest
from research.validate import validate_dataset
from research.metrics import (
    cohens_kappa, confusion_matrix, per_class_prf, accuracy,
    fleiss_kappa, self_agreement_rate, pairwise_agreement, bootstrap_ci,
)
from agentprobe.models import parse_model_size_b

# Everything is compared in the human 3-class vocabulary.
CLASSES = ["COMPLIED", "PARTIAL", "REFUSED"]
INTERNAL_TO_LABEL = {"VULNERABLE": "COMPLIED", "PARTIAL": "PARTIAL",
                     "SAFE": "REFUSED", "SUSPICIOUS": "SUSPICIOUS"}


def _json_safe(value):
    """Convert undefined numeric metrics to strict-JSON ``null`` values."""

    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    return value


def load_label_rows(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_labels(path):
    """response_id -> {labeler: label}."""
    out = defaultdict(dict)
    for row in load_label_rows(path):
        out[row["response_id"]][row["labeler"]] = row["label"]
    return out


def judge_majority(judgements):
    """(response_id, judge_model, temp) -> majority label + the k raw verdicts."""
    groups = defaultdict(list)
    for j in judgements:
        # An operational failure is not a model judgment. Keeping it as
        # SUSPICIOUS makes outages look like model disagreement and pollutes
        # both validity and reliability estimates.
        if j.get("error"):
            continue
        lab = INTERNAL_TO_LABEL.get(j.get("verdict"))
        if lab is None:
            continue
        groups[(j["response_id"], j["judge_model"], float(j["temperature"]))].append(lab)
    majo = {}
    for key, verdicts in groups.items():
        counts = Counter(verdicts)
        top = counts.most_common()
        # A tie is not a majority. Marking it unscorable is safer than making
        # the result depend on JSONL row order.
        if len(top) > 1 and top[0][1] == top[1][1]:
            label = "SUSPICIOUS"
        else:
            label = top[0][0]
        majo[key] = (label, verdicts)
    return majo


def _model_size_b(model):
    """Best-effort parameter-size extraction for an explicit fallback."""
    return parse_model_size_b(model)


def choose_reference_config(judge_majo, preferred_model=None,
                            preferred_temperature=None):
    """Select the judge configuration used for RQ3.

    The configured judge is authoritative when available. If callers do not
    provide one, prefer the largest parseable model name, then the lowest
    temperature. This prevents lexical model-name ordering from silently
    selecting a weaker judge as the reference.
    """
    configs = sorted({(model, float(temp)) for (_rid, model, temp) in judge_majo})
    if not configs:
        return None

    if preferred_model:
        matching = [c for c in configs if c[0] == preferred_model]
        if not matching:
            raise ValueError(f"reference judge configuration not found: {preferred_model}")
        if preferred_temperature is not None:
            exact = [c for c in matching if c[1] == float(preferred_temperature)]
            if not exact:
                raise ValueError(
                    f"reference temperature {preferred_temperature} not found for {preferred_model}"
                )
            return exact[0]
        return min(matching, key=lambda c: c[1])

    if preferred_temperature is not None:
        matching = [c for c in configs if c[1] == float(preferred_temperature)]
        if not matching:
            raise ValueError(f"reference temperature not found: {preferred_temperature}")
        return max(
            matching,
            key=lambda c: (_model_size_b(c[0]) is not None, _model_size_b(c[0]) or -1, c[0]),
        )

    return max(
        configs,
        key=lambda c: (
            _model_size_b(c[0]) is not None,
            _model_size_b(c[0]) or -1,
            c[0],
            -c[1],
        ),
    )


def choose_weak_config(judge_majo, preferred_model=None,
                       preferred_temperature=None):
    """Select the smallest available judge config for the RQ4 comparison."""
    configs = sorted({(model, float(temp)) for (_rid, model, temp) in judge_majo})
    if not configs:
        return None
    if preferred_model:
        matching = [c for c in configs if c[0] == preferred_model]
        if not matching:
            raise ValueError(f"weak judge configuration not found: {preferred_model}")
        if preferred_temperature is not None:
            exact = [c for c in matching if c[1] == float(preferred_temperature)]
            if not exact:
                raise ValueError(
                    f"weak judge temperature {preferred_temperature} not found for {preferred_model}"
                )
            return exact[0]
        return min(matching, key=lambda c: c[1])

    if preferred_temperature is not None:
        matching = [c for c in configs if c[1] == float(preferred_temperature)]
        if not matching:
            raise ValueError(f"weak judge temperature not found: {preferred_temperature}")
        return min(
            matching,
            key=lambda c: (
                _model_size_b(c[0]) is None,
                _model_size_b(c[0]) if _model_size_b(c[0]) is not None else float("inf"),
                c[0],
            ),
        )
    return min(
        configs,
        key=lambda c: (
            _model_size_b(c[0]) is None,
            _model_size_b(c[0]) if _model_size_b(c[0]) is not None else float("inf"),
            c[0],
            c[1],
        ),
    )


def fmt_kappa(k):
    return "n/a" if k is None or k != k else f"{k:.3f}"  # catches None/NaN


def print_confusion(title, cm, labels):
    print(f"  {title}")
    header = "    gold\\pred  " + "".join(f"{label[:7]:>9}" for label in labels)
    print(header)
    for g in labels:
        row = "".join(f"{cm[g][p]:>9}" for p in labels)
        print(f"    {g[:9]:<11}{row}")


def rq1_validity(corpus_by_id, labels, judge_majo, primary, out):
    print("\n=== RQ1 — Validity: judge vs human ===")
    # Group by judge config so a strong and weak judge are reported separately.
    configs = sorted({(m, t) for (_r, m, t) in judge_majo})
    for model, temp in configs:
        pairs = []
        category_pairs = defaultdict(list)
        for rid, lab_map in labels.items():
            gold = lab_map.get(primary)
            jm = judge_majo.get((rid, model, temp))
            if gold in CLASSES and jm and jm[0] in CLASSES:
                pairs.append((gold, jm[0]))
                category = corpus_by_id.get(rid, {}).get("category", "unknown")
                category_pairs[category].append((gold, jm[0]))
        if not pairs:
            print(f"  [{model} @ {temp}] no overlapping labeled responses yet.")
            continue
        k = cohens_kappa(pairs, CLASSES)
        acc = accuracy(pairs)
        acc_ci = bootstrap_ci(pairs, accuracy, seed=17)
        kappa_ci = bootstrap_ci(
            pairs, lambda sample: cohens_kappa(sample, CLASSES), seed=23,
        )
        cm = confusion_matrix(pairs, CLASSES)
        prf = per_class_prf(pairs, CLASSES)
        print(f"\n  Judge {model} @ temp {temp}  (n={len(pairs)})")
        print(f"    accuracy = {acc:.3f}   Cohen's kappa = {fmt_kappa(k)}")
        print(f"    95% bootstrap CI: accuracy [{acc_ci[0]:.3f}, {acc_ci[1]:.3f}]  "
              f"kappa [{fmt_kappa(kappa_ci[0])}, {fmt_kappa(kappa_ci[1])}]")
        for c in CLASSES:
            p = prf[c]
            print(f"      {c:<9} P={p['precision']:.2f} R={p['recall']:.2f} "
                  f"F1={p['f1']:.2f} (support {p['support']})")
        print_confusion("confusion (human gold vs judge pred):", cm, CLASSES)
        by_category = {}
        for category, category_values in sorted(category_pairs.items()):
            by_category[category] = {
                "n": len(category_values),
                "accuracy": accuracy(category_values),
                "cohens_kappa": cohens_kappa(category_values, CLASSES),
                "confusion": confusion_matrix(category_values, CLASSES),
            }
        out["rq1"].append({"judge_model": model, "temperature": temp,
                           "n": len(pairs), "accuracy": acc, "cohens_kappa": k,
                           "accuracy_ci_95": list(acc_ci),
                           "cohens_kappa_ci_95": list(kappa_ci),
                           "per_class": prf, "confusion": cm,
                           "by_category": by_category})


def rq2_reliability(judgements, out, expected_response_ids=None):
    print("\n=== RQ2 — Reliability: judge vs itself across k runs ===")
    groups = defaultdict(list)
    error_counts = Counter()
    for j in judgements:
        key = (j.get("judge_model"), float(j.get("temperature", 0.0)))
        if j.get("error"):
            error_counts[key] += 1
            continue
        lab = INTERNAL_TO_LABEL.get(j.get("verdict"))
        if lab is None:
            continue
        groups[key].append((j["response_id"], lab))
    labels_all = CLASSES + ["SUSPICIOUS"]
    for (model, temp), items in sorted(groups.items()):
        per_item = defaultdict(list)
        for rid, lab in items:
            per_item[rid].append(lab)
        if expected_response_ids is None:
            item_runs = sorted(per_item.items())
        else:
            item_runs = [(rid, per_item.get(rid, [])) for rid in sorted(expected_response_ids)]
        runs_all = [runs for _rid, runs in item_runs]
        observed_ks = [len(v) for v in runs_all if v]
        # Fleiss' kappa is defined for a fixed rater count. If an interrupted
        # run leaves uneven groups, keep only the modal complete count and make
        # the exclusion visible instead of publishing an invalid statistic.
        count_freq = Counter(observed_ks)
        expected_k = max(count_freq, key=lambda k: (count_freq[k], k)) if observed_ks else 0
        runs = [v for v in runs_all if len(v) == expected_k]
        flipped_response_ids = [
            rid for (rid, values) in item_runs
            if len(values) == expected_k and len(set(values)) > 1
        ]
        item_ratings = [{label: v.count(label) for label in labels_all} for v in runs]
        fk = fleiss_kappa(item_ratings, labels_all) if runs else float("nan")
        sar = self_agreement_rate(runs)
        pw = pairwise_agreement(runs)
        flips = len(flipped_response_ids)
        fk_ci = bootstrap_ci(
            runs,
            lambda sample: fleiss_kappa(
                [{label: v.count(label) for label in labels_all} for v in sample], labels_all
            ),
            seed=31,
        )
        sar_ci = bootstrap_ci(runs, self_agreement_rate, seed=37)
        print(f"\n  Judge {model} @ temp {temp}  "
              f"(items={len(runs)}/{len(runs_all)}, k={expected_k}"
              f"{'' if len(set(observed_ks))==1 and len(runs)==len(runs_all) else ' [uneven; incomplete items excluded]'})")
        print(f"    self-agreement = {sar:.3f}   pairwise = {pw:.3f}   "
              f"Fleiss' kappa = {fmt_kappa(fk)}")
        print(f"    95% bootstrap CI: self-agreement [{fmt_kappa(sar_ci[0])}, "
              f"{fmt_kappa(sar_ci[1])}]  kappa [{fmt_kappa(fk_ci[0])}, "
              f"{fmt_kappa(fk_ci[1])}]")
        print(f"    items that ever flipped: {flips}/{len(runs)}")
        error_count = error_counts[(model, temp)]
        if error_count:
            print(f"    operational judge errors excluded: {error_count}")
        out["rq2"].append({"judge_model": model, "temperature": temp,
                           "items": len(runs), "self_agreement": sar,
                           "pairwise": pw, "fleiss_kappa": fk, "flipped": flips,
                           "flipped_response_ids": flipped_response_ids,
                           "self_agreement_ci_95": list(sar_ci),
                           "fleiss_kappa_ci_95": list(fk_ci),
                           "observed_item_counts": dict(sorted(count_freq.items())),
                           "expected_k": expected_k,
                           "incomplete_items_excluded": len(runs_all) - len(runs),
                           "missing_item_groups": sum(1 for v in runs_all if not v),
                           "judge_errors_excluded": error_count})


def rq3_keyword_vs_judge(corpus, judge_majo, out, reference_model=None,
                         reference_temperature=None):
    print("\n=== RQ3 — Keyword stage vs judge ===")
    reference = choose_reference_config(
        judge_majo,
        preferred_model=reference_model,
        preferred_temperature=reference_temperature,
    )
    if reference is None:
        print("  no judgements yet.")
        return
    ref_model, ref_temp = reference
    pairs = []
    for row in corpus:
        kwlab = INTERNAL_TO_LABEL.get(row["keyword_verdict"], "SUSPICIOUS")
        jm = judge_majo.get((row["response_id"], ref_model, ref_temp))
        if jm:
            pairs.append((kwlab, jm[0]))
    labels_all = CLASSES + ["SUSPICIOUS"]
    cm = confusion_matrix(pairs, labels_all)
    disagreements = []
    for row in corpus:
        kwlab = INTERNAL_TO_LABEL.get(row["keyword_verdict"], "SUSPICIOUS")
        jm = judge_majo.get((row["response_id"], ref_model, ref_temp))
        if jm and kwlab != jm[0]:
            disagreements.append({
                "response_id": row["response_id"],
                "keyword": kwlab,
                "judge": jm[0],
            })
    agree = accuracy(pairs)
    print(f"  reference judge: {ref_model} @ {ref_temp}   (n={len(pairs)})")
    print(f"  raw agreement (all 4 classes) = {agree:.3f}")
    print_confusion("confusion (keyword vs judge):", cm, labels_all)
    # Where does the FREE path decide, and is it safe when it does?
    decisive = [row for row in corpus if row.get("keyword_decisive")]
    print(f"  keyword decided on its own (decisive): {len(decisive)}/{len(corpus)} "
          f"= {len(decisive)/len(corpus):.1%}" if corpus else "  (empty corpus)")
    out["rq3"] = {"reference_judge": ref_model, "temperature": ref_temp,
                  "n": len(pairs), "raw_agreement": agree,
                  "keyword_decisive_rate": (len(decisive)/len(corpus)) if corpus else None,
                  "confusion": cm, "disagreements": disagreements}


def rq4_proxy_error_overlap(corpus, labels, judge_majo, primary, out,
                            weak_model=None, weak_temperature=None):
    """Measure overlap between weak-judge and keyword errors on human labels.

    The keyword stage is only a target-behavior proxy, not independent ground
    truth. This is why the result is named *proxy* error overlap and why the
    report also gives the usable n and excluded ambiguous keyword cases.
    """
    weak = choose_weak_config(
        judge_majo,
        preferred_model=weak_model,
        preferred_temperature=weak_temperature,
    )
    if weak is None:
        return
    weak_model, weak_temp = weak
    pairs = []
    excluded_keyword = 0
    for row in corpus:
        gold = labels.get(row["response_id"], {}).get(primary)
        keyword = INTERNAL_TO_LABEL.get(row.get("keyword_verdict"))
        judged = judge_majo.get((row["response_id"], weak_model, weak_temp))
        if gold not in CLASSES or not judged or judged[0] not in CLASSES:
            continue
        if keyword not in CLASSES:
            excluded_keyword += 1
            continue
        pairs.append((gold, keyword, judged[0]))
    if not pairs:
        print("\n=== RQ4 — Proxy error overlap ===\n  no complete labeled items yet.")
        return

    keyword_errors = sum(keyword != gold for gold, keyword, _judge in pairs)
    judge_errors = sum(judge != gold for gold, _keyword, judge in pairs)
    joint_errors = sum(keyword != gold and judge != gold for gold, keyword, judge in pairs)
    union_errors = sum(keyword != gold or judge != gold for gold, keyword, judge in pairs)
    disagreement = sum(keyword != judge for gold, keyword, judge in pairs)
    def overlap_statistic(sample):
        joint = sum(keyword != gold and judge != gold for gold, keyword, judge in sample)
        union = sum(keyword != gold or judge != gold for gold, keyword, judge in sample)
        return joint / union if union else float("nan")

    def disagreement_statistic(sample):
        return (sum(keyword != judge for _gold, keyword, judge in sample) / len(sample)
                if sample else float("nan"))

    overlap_ci = bootstrap_ci(pairs, overlap_statistic, seed=41)
    disagreement_ci = bootstrap_ci(pairs, disagreement_statistic, seed=43)
    result = {
        "weak_judge": weak_model,
        "temperature": weak_temp,
        "n": len(pairs),
        "keyword_proxy_errors": keyword_errors,
        "weak_judge_errors": judge_errors,
        "joint_errors": joint_errors,
        "error_union": union_errors,
        "error_overlap_rate": (joint_errors / union_errors) if union_errors else None,
        "error_overlap_rate_ci_95": list(overlap_ci),
        "joint_given_keyword_error": (joint_errors / keyword_errors) if keyword_errors else None,
        "keyword_judge_disagreement": disagreement / len(pairs),
        "keyword_judge_disagreement_ci_95": list(disagreement_ci),
        "ambiguous_keyword_items_excluded": excluded_keyword,
        "interpretation": "keyword output is a target-behavior proxy, not independent ground truth",
    }
    print("\n=== RQ4 — Proxy error overlap ===")
    print(f"  weak judge: {weak_model} @ {weak_temp}   (n={len(pairs)})")
    print(f"  keyword proxy errors: {keyword_errors}   weak-judge errors: {judge_errors}")
    print(f"  joint errors: {joint_errors}   overlap of error union: {fmt_kappa(result['error_overlap_rate'])}")
    print(f"  95% bootstrap CI: overlap [{fmt_kappa(overlap_ci[0])}, {fmt_kappa(overlap_ci[1])}]  "
          f"keyword/judge disagreement [{fmt_kappa(disagreement_ci[0])}, "
          f"{fmt_kappa(disagreement_ci[1])}]")
    if excluded_keyword:
        print(f"  ambiguous keyword items excluded: {excluded_keyword}")
    out["rq4_proxy_error_overlap"] = result


def inter_annotator(labels, primary, second, out):
    if not second:
        return
    pairs = []
    for rid, lab_map in labels.items():
        a, b = lab_map.get(primary), lab_map.get(second)
        if a in CLASSES and b in CLASSES:
            pairs.append((a, b))
    print("\n=== Inter-annotator agreement (two humans) ===")
    if not pairs:
        print(f"  no responses labeled by BOTH '{primary}' and '{second}' yet.")
        return
    k = cohens_kappa(pairs, CLASSES)
    print(f"  '{primary}' vs '{second}'  (n={len(pairs)}): "
          f"accuracy={accuracy(pairs):.3f}  Cohen's kappa={fmt_kappa(k)}")
    print("  (this is the ceiling — the judge can't be expected to beat two humans)")
    out["inter_annotator"] = {"primary": primary, "second": second,
                              "n": len(pairs), "cohens_kappa": k}


def main():
    ap = argparse.ArgumentParser(description="Analyze corpus/judgements/labels (Steps D/E).")
    ap.add_argument("--corpus", default="data/corpus.jsonl")
    ap.add_argument("--judgements", default="data/judgements.jsonl")
    ap.add_argument("--labels", default="data/labels.csv")
    ap.add_argument("--primary", default=None, help="primary human labeler name")
    ap.add_argument("--second", default=None, help="second labeler name for IAA")
    ap.add_argument("--reference-judge", default=None,
                    help="judge model to use for RQ3 (default: config judge.model)")
    ap.add_argument("--reference-temperature", type=float, default=None,
                    help="exact RQ3 judge temperature (default: lowest available)")
    ap.add_argument("--weak-judge", default=None,
                    help="judge model to use for RQ4 proxy error overlap")
    ap.add_argument("--weak-temperature", type=float, default=None,
                    help="exact RQ4 judge temperature (default: lowest available)")
    ap.add_argument("--manifest", default=DEFAULT_MANIFEST_PATH,
                    help="study protocol used for default labelers and judge selections")
    ap.add_argument("--config", default="config.yaml",
                    help="scanner config used to select the configured reference judge")
    ap.add_argument("--json", default=None, help="write machine-readable summary here")
    args = ap.parse_args()
    for name in ("reference_temperature", "weak_temperature"):
        value = getattr(args, name)
        if value is not None and (not math.isfinite(value) or not 0 <= value <= 2):
            ap.error(f"--{name.replace('_', '-')} must be between 0 and 2")

    manifest = None
    if args.manifest and os.path.exists(args.manifest):
        try:
            manifest = load_manifest(args.manifest)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            ap.error(f"invalid study manifest: {exc}")
    primary = args.primary or (manifest or {}).get("labels", {}).get("primary", "primary")
    second = args.second
    if second is None and manifest:
        second = manifest["labels"]["second"]
    reference_model = args.reference_judge
    reference_temperature = args.reference_temperature
    weak_model = args.weak_judge
    weak_temperature = args.weak_temperature
    if manifest:
        reference = manifest["analysis"]["reference"]
        weak = manifest["analysis"]["weak"]
        reference_model = reference_model or reference["model"]
        reference_temperature = (
            reference_temperature if reference_temperature is not None
            else reference["temperature"]
        )
        weak_model = weak_model or weak["model"]
        weak_temperature = (
            weak_temperature if weak_temperature is not None else weak["temperature"]
        )

    corpus = read_jsonl(args.corpus) if os.path.exists(args.corpus) else []
    judgements = read_jsonl(args.judgements) if os.path.exists(args.judgements) else []
    label_rows = load_label_rows(args.labels)
    validation = validate_dataset(corpus, judgements, label_rows, ATTACK_LIBRARY)
    if not validation["valid"]:
        for error in validation["errors"]:
            print(f"ERROR: {error}")
        raise SystemExit("Input validation failed; run research.validate for details.")
    for warning in validation["warnings"]:
        print(f"WARNING: {warning}")
    labels = defaultdict(dict)
    for row in label_rows:
        labels[row["response_id"]][row["labeler"]] = row["label"]
    corpus_by_id = {r["response_id"]: r for r in corpus}
    judge_majo = judge_majority(judgements)

    print("=" * 64)
    print("AGENTPROBE — research analysis")
    print(f"  corpus responses : {len(corpus)}")
    print(f"  judge calls      : {len(judgements)}")
    print(f"  labeled responses: {len(labels)}")
    print("=" * 64)

    out = {
        "analysis_version": "1.0",
        "metadata": {
            "corpus_responses": len(corpus),
            "corpus_sha256": canonical_digest(corpus),
            "judge_rows": len(judgements),
            "label_rows": sum(len(values) for values in labels.values()),
            "primary_labeler": primary,
            "second_labeler": second,
            "protocol_manifest_sha256": manifest_digest(manifest) if manifest else None,
            "labeling_guide_sha256": (
                manifest.get("labeling_guide_sha256") if manifest else None
            ),
        },
        "rq1": [], "rq2": [], "rq3": {}, "inter_annotator": {},
    }
    if judgements:
        rq2_reliability(judgements, out,
                        expected_response_ids={r["response_id"] for r in corpus})
    if labels and judge_majo:
        rq1_validity(corpus_by_id, labels, judge_majo, primary, out)
    if corpus and judge_majo:
        configured_reference = reference_model
        if configured_reference is None and os.path.exists(args.config):
            config = load_config(args.config) or {}
            configured_reference = (config.get("judge") or {}).get("model")
        rq3_keyword_vs_judge(corpus, judge_majo, out,
                             reference_model=configured_reference,
                             reference_temperature=reference_temperature)
    if corpus and labels and judge_majo:
        rq4_proxy_error_overlap(corpus, labels, judge_majo, primary, out,
                                 weak_model=weak_model,
                                 weak_temperature=weak_temperature)
    inter_annotator(labels, primary, second, out)

    if not (corpus or judgements or labels):
        print("\nNo data yet. Run gen_corpus -> run_judges -> label, then re-run.")

    if args.json:
        os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
        with open(args.json, "w") as f:
            json.dump(_json_safe(out), f, indent=2, allow_nan=False)
        print(f"\nWrote machine-readable summary to {args.json}")


if __name__ == "__main__":
    main()
