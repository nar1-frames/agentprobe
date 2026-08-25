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
#   python -m research.analyze --primary ren --second friend --json data/results.json
# ============================================================

import argparse
import csv
import json
import os
from collections import defaultdict, Counter

from research._common import read_jsonl
from research.metrics import (
    cohens_kappa, confusion_matrix, per_class_prf, accuracy,
    fleiss_kappa, self_agreement_rate, pairwise_agreement,
)

# Everything is compared in the human 3-class vocabulary.
CLASSES = ["COMPLIED", "PARTIAL", "REFUSED"]
INTERNAL_TO_LABEL = {"VULNERABLE": "COMPLIED", "PARTIAL": "PARTIAL",
                     "SAFE": "REFUSED", "SUSPICIOUS": "SUSPICIOUS"}


def load_labels(path):
    """response_id -> {labeler: label}."""
    out = defaultdict(dict)
    if not os.path.exists(path):
        return out
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            out[row["response_id"]][row["labeler"]] = row["label"]
    return out


def judge_majority(judgements):
    """(response_id, judge_model, temp) -> majority label + the k raw verdicts."""
    groups = defaultdict(list)
    for j in judgements:
        lab = INTERNAL_TO_LABEL.get(j["verdict"], "SUSPICIOUS")
        groups[(j["response_id"], j["judge_model"], j["temperature"])].append(lab)
    majo = {}
    for key, verdicts in groups.items():
        counts = Counter(verdicts)
        majo[key] = (counts.most_common(1)[0][0], verdicts)
    return majo


def fmt_kappa(k):
    return "n/a" if k != k else f"{k:.3f}"  # k!=k catches NaN


def print_confusion(title, cm, labels):
    print(f"  {title}")
    header = "    gold\\pred  " + "".join(f"{l[:7]:>9}" for l in labels)
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
        for rid, lab_map in labels.items():
            gold = lab_map.get(primary)
            jm = judge_majo.get((rid, model, temp))
            if gold in CLASSES and jm and jm[0] in CLASSES:
                pairs.append((gold, jm[0]))
        if not pairs:
            print(f"  [{model} @ {temp}] no overlapping labeled responses yet.")
            continue
        k = cohens_kappa(pairs, CLASSES)
        acc = accuracy(pairs)
        cm = confusion_matrix(pairs, CLASSES)
        prf = per_class_prf(pairs, CLASSES)
        print(f"\n  Judge {model} @ temp {temp}  (n={len(pairs)})")
        print(f"    accuracy = {acc:.3f}   Cohen's kappa = {fmt_kappa(k)}")
        for c in CLASSES:
            p = prf[c]
            print(f"      {c:<9} P={p['precision']:.2f} R={p['recall']:.2f} "
                  f"F1={p['f1']:.2f} (support {p['support']})")
        print_confusion("confusion (human gold vs judge pred):", cm, CLASSES)
        out["rq1"].append({"judge_model": model, "temperature": temp,
                           "n": len(pairs), "accuracy": acc, "cohens_kappa": k,
                           "per_class": prf})


def rq2_reliability(judgements, out):
    print("\n=== RQ2 — Reliability: judge vs itself across k runs ===")
    groups = defaultdict(list)
    for j in judgements:
        lab = INTERNAL_TO_LABEL.get(j["verdict"], "SUSPICIOUS")
        groups[(j["judge_model"], j["temperature"])].append((j["response_id"], lab))
    labels_all = CLASSES + ["SUSPICIOUS"]
    for (model, temp), items in sorted(groups.items()):
        per_item = defaultdict(list)
        for rid, lab in items:
            per_item[rid].append(lab)
        runs = list(per_item.values())
        ks = [len(v) for v in runs]
        item_ratings = [{l: v.count(l) for l in labels_all} for v in runs]
        fk = fleiss_kappa(item_ratings, labels_all)
        sar = self_agreement_rate(runs)
        pw = pairwise_agreement(runs)
        flips = sum(1 for v in runs if len(set(v)) > 1)
        print(f"\n  Judge {model} @ temp {temp}  "
              f"(items={len(runs)}, k={min(ks) if ks else 0}"
              f"{'' if len(set(ks))==1 else ' [uneven]'})")
        print(f"    self-agreement = {sar:.3f}   pairwise = {pw:.3f}   "
              f"Fleiss' kappa = {fmt_kappa(fk)}")
        print(f"    items that ever flipped: {flips}/{len(runs)}")
        out["rq2"].append({"judge_model": model, "temperature": temp,
                           "items": len(runs), "self_agreement": sar,
                           "pairwise": pw, "fleiss_kappa": fk, "flipped": flips})


def rq3_keyword_vs_judge(corpus, judge_majo, out):
    print("\n=== RQ3 — Keyword stage vs judge ===")
    # Use the strongest available judge config (first sorted) as reference.
    configs = sorted({(m, t) for (_r, m, t) in judge_majo})
    if not configs:
        print("  no judgements yet.")
        return
    ref_model, ref_temp = configs[0]
    pairs = []
    for row in corpus:
        kwlab = INTERNAL_TO_LABEL.get(row["keyword_verdict"], "SUSPICIOUS")
        jm = judge_majo.get((row["response_id"], ref_model, ref_temp))
        if jm:
            pairs.append((kwlab, jm[0]))
    labels_all = CLASSES + ["SUSPICIOUS"]
    cm = confusion_matrix(pairs, labels_all)
    agree = accuracy(pairs)
    print(f"  reference judge: {ref_model} @ {ref_temp}   (n={len(pairs)})")
    print(f"  raw agreement (all 4 classes) = {agree:.3f}")
    print_confusion("confusion (keyword vs judge):", cm, labels_all)
    # Where does the FREE path decide, and is it safe when it does?
    decisive = [row for row in corpus if row.get("keyword_decisive")]
    print(f"  keyword decided on its own (decisive): {len(decisive)}/{len(corpus)} "
          f"= {len(decisive)/len(corpus):.1%}" if corpus else "  (empty corpus)")
    out["rq3"] = {"reference_judge": ref_model, "temperature": ref_temp,
                  "raw_agreement": agree,
                  "keyword_decisive_rate": (len(decisive)/len(corpus)) if corpus else None}


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
    ap.add_argument("--primary", default="primary", help="primary human labeler name")
    ap.add_argument("--second", default=None, help="second labeler name for IAA")
    ap.add_argument("--json", default=None, help="write machine-readable summary here")
    args = ap.parse_args()

    corpus = read_jsonl(args.corpus) if os.path.exists(args.corpus) else []
    judgements = read_jsonl(args.judgements) if os.path.exists(args.judgements) else []
    labels = load_labels(args.labels)
    corpus_by_id = {r["response_id"]: r for r in corpus}
    judge_majo = judge_majority(judgements)

    print("=" * 64)
    print("AGENTPROBE — research analysis")
    print(f"  corpus responses : {len(corpus)}")
    print(f"  judge calls      : {len(judgements)}")
    print(f"  labeled responses: {len(labels)}")
    print("=" * 64)

    out = {"rq1": [], "rq2": [], "rq3": {}, "inter_annotator": {}}
    if judgements:
        rq2_reliability(judgements, out)
    if labels and judge_majo:
        rq1_validity(corpus_by_id, labels, judge_majo, args.primary, out)
    if corpus and judge_majo:
        rq3_keyword_vs_judge(corpus, judge_majo, out)
    inter_annotator(labels, args.primary, args.second, out)

    if not (corpus or judgements or labels):
        print("\nNo data yet. Run gen_corpus -> run_judges -> label, then re-run.")

    if args.json:
        os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
        with open(args.json, "w") as f:
            json.dump(out, f, indent=2)
        print(f"\nWrote machine-readable summary to {args.json}")


if __name__ == "__main__":
    main()
