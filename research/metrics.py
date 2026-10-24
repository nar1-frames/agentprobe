# ============================================================
# Agreement metrics — pure Python, no sklearn required
# ============================================================
# These are deliberately dependency-free and short enough to read,
# because in a methods paper you must be able to say exactly what
# your kappa computed. Every function has a docstring you could
# paste into the appendix.
# ============================================================

from collections import Counter
from itertools import combinations
import random


def confusion_matrix(pairs, labels):
    """pairs: iterable of (gold, pred). Returns nested dict [gold][pred] = count."""
    m = {g: {p: 0 for p in labels} for g in labels}
    for gold, pred in pairs:
        if gold in m and pred in m[gold]:
            m[gold][pred] += 1
    return m


def accuracy(pairs):
    pairs = list(pairs)
    if not pairs:
        return 0.0
    return sum(1 for a, b in pairs if a == b) / len(pairs)


def bootstrap_ci(values, statistic, iterations=2000, confidence=0.95, seed=42):
    """Deterministic percentile bootstrap confidence interval.

    ``values`` is a finite sequence of observations and ``statistic`` is a
    callable accepting a resampled list. The fixed seed makes paper tables
    reproducible while still exposing the uncertainty caused by a small sample.
    """
    values = list(values)
    if not values:
        return (float("nan"), float("nan"))
    if iterations < 1 or not 0 < confidence < 1:
        raise ValueError("iterations must be positive and confidence must be between 0 and 1")
    rng = random.Random(seed)
    estimates = []
    for _ in range(iterations):
        sample = [values[rng.randrange(len(values))] for _ in values]
        estimate = statistic(sample)
        if estimate == estimate:  # skip NaN statistics, if a caller produces one
            estimates.append(estimate)
    if not estimates:
        return (float("nan"), float("nan"))
    estimates.sort()
    alpha = (1 - confidence) / 2
    low = int(alpha * (len(estimates) - 1))
    high = int((1 - alpha) * (len(estimates) - 1))
    return estimates[low], estimates[high]


def cohens_kappa(pairs, labels=None):
    """Cohen's kappa for two raters over paired categorical judgments.

    kappa = (p_o - p_e) / (1 - p_e), where p_o is observed agreement and
    p_e is agreement expected if each rater labeled independently at their
    own marginal rates. kappa = 0 means "no better than chance"; 1 means
    perfect. This is why we lead with kappa, not accuracy: if 70% of
    responses are REFUSED, a rater who always says REFUSED scores .70
    accuracy and kappa ~ 0.
    """
    pairs = [(a, b) for a, b in pairs if a is not None and b is not None]
    if not pairs:
        return float("nan")
    if labels is None:
        labels = sorted({a for a, _ in pairs} | {b for _, b in pairs})
    n = len(pairs)
    p_o = accuracy(pairs)
    a_marg = Counter(a for a, _ in pairs)
    b_marg = Counter(b for _, b in pairs)
    p_e = sum((a_marg[label] / n) * (b_marg[label] / n) for label in labels)
    if p_e == 1.0:
        return 1.0
    return (p_o - p_e) / (1 - p_e)


def per_class_prf(pairs, labels):
    """Precision/recall/F1 per class, treating the first element as gold."""
    out = {}
    for label in labels:
        tp = sum(1 for g, p in pairs if g == label and p == label)
        fp = sum(1 for g, p in pairs if g != label and p == label)
        fn = sum(1 for g, p in pairs if g == label and p != label)
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        out[label] = {"precision": prec, "recall": rec, "f1": f1,
                      "support": sum(1 for g, _ in pairs if g == label)}
    return out


def fleiss_kappa(item_ratings, labels):
    """Fleiss' kappa: agreement among a fixed number of raters per item.

    item_ratings: list of dicts {label: count} — for each item, how many of
    the n raters chose each label. Here an "item" is one response and the
    "raters" are the k repeated judge runs of a single config, so this
    measures whether the judge agrees with ITSELF across runs (RQ2 —
    reliability). Requires the same rater count n for every item.
    """
    items = [r for r in item_ratings if sum(r.values()) > 0]
    if not items:
        return float("nan")
    counts = [sum(r.get(label, 0) for label in labels) for r in items]
    if len(set(counts)) != 1:
        raise ValueError(
            "Fleiss' kappa requires the same number of raters for every item; "
            f"got counts {sorted(set(counts))}"
        )
    n = counts[0]
    if n <= 1:
        return float("nan")  # need >=2 raters (k>=2) to talk about agreement
    N = len(items)

    # P_i: agreement within item i
    P = []
    for r in items:
        s = sum(r.get(label, 0) * (r.get(label, 0) - 1) for label in labels)
        P.append(s / (n * (n - 1)))
    P_bar = sum(P) / N

    # p_j: proportion of all assignments to category j
    total = N * n
    p_j = {label: sum(r.get(label, 0) for r in items) / total for label in labels}
    P_e = sum(v * v for v in p_j.values())

    if P_e == 1.0:
        return 1.0
    return (P_bar - P_e) / (1 - P_e)


def self_agreement_rate(runs):
    """Fraction of runs equal to the modal verdict (per item), averaged.

    A blunter, more intuitive companion to Fleiss' kappa: '4 of 5 runs
    agreed' reads to anyone. runs: list of lists, each inner list = the k
    verdicts for one item.
    """
    rates = []
    for verdicts in runs:
        if not verdicts:
            continue
        modal = Counter(verdicts).most_common(1)[0][1]
        rates.append(modal / len(verdicts))
    return sum(rates) / len(rates) if rates else float("nan")


def pairwise_agreement(runs):
    """Mean pairwise exact-agreement across the k runs of each item."""
    vals = []
    for verdicts in runs:
        if len(verdicts) < 2:
            continue
        pairs = list(combinations(verdicts, 2))
        vals.append(sum(1 for a, b in pairs if a == b) / len(pairs))
    return sum(vals) / len(vals) if vals else float("nan")
