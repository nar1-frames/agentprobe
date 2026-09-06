# Sanity checks for the pure-Python agreement metrics.
# Values are checked against known closed-form cases so we can trust
# the numbers that will go in the paper.

import math
import pytest
from research.metrics import (
    cohens_kappa, accuracy, fleiss_kappa, self_agreement_rate, bootstrap_ci,
)

L = ["COMPLIED", "PARTIAL", "REFUSED"]


def test_perfect_agreement_kappa_is_one():
    pairs = [("REFUSED", "REFUSED")] * 5 + [("COMPLIED", "COMPLIED")] * 5
    assert cohens_kappa(pairs, L) == 1.0


def test_kappa_zero_when_only_chance_agreement():
    # Rater A always REFUSED; rater B always REFUSED -> p_e = 1 -> defined as 1.
    # Instead test the "no better than chance" property with independent marginals:
    # A: 50/50 C/R, B: 50/50 C/R, arranged so observed == expected.
    pairs = [("COMPLIED", "COMPLIED"), ("COMPLIED", "REFUSED"),
             ("REFUSED", "COMPLIED"), ("REFUSED", "REFUSED")]
    k = cohens_kappa(pairs, ["COMPLIED", "REFUSED"])
    assert math.isclose(k, 0.0, abs_tol=1e-9)


def test_accuracy_ignores_kappa_lesson():
    # 8 REFUSED, 2 COMPLIED; a lazy 'always REFUSED' judge.
    gold = ["REFUSED"] * 8 + ["COMPLIED"] * 2
    pred = ["REFUSED"] * 10
    pairs = list(zip(gold, pred))
    assert accuracy(pairs) == 0.8            # looks great...
    assert cohens_kappa(pairs, L) <= 0.0     # ...but kappa exposes it


def test_fleiss_perfect():
    # every item: all 5 raters chose the same label
    items = [{"COMPLIED": 5, "PARTIAL": 0, "REFUSED": 0},
             {"COMPLIED": 0, "PARTIAL": 0, "REFUSED": 5}]
    assert fleiss_kappa(items, L) == 1.0


def test_fleiss_rejects_uneven_rater_counts():
    with pytest.raises(ValueError, match="same number of raters"):
        fleiss_kappa([
            {"COMPLIED": 3, "PARTIAL": 0, "REFUSED": 0},
            {"COMPLIED": 2, "PARTIAL": 0, "REFUSED": 0},
        ], L)


def test_self_agreement_rate_basic():
    runs = [["A", "A", "A", "B"], ["A", "A", "A", "A"]]
    # item1: 3/4, item2: 4/4 -> mean = 0.875
    assert math.isclose(self_agreement_rate(runs), 0.875, abs_tol=1e-9)


def test_bootstrap_ci_is_reproducible_and_contains_observed_mean():
    values = [0, 1, 1, 1, 0]
    first = bootstrap_ci(values, lambda sample: sum(sample) / len(sample), seed=99)
    second = bootstrap_ci(values, lambda sample: sum(sample) / len(sample), seed=99)
    assert first == second
    assert first[0] <= 0.6 <= first[1]
