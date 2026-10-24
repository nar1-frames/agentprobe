"""The committed sample retest is exactly what the code renders from its inputs."""

import json
import re
from pathlib import Path

import yaml

from agentprobe.customer_report import render_customer_report


SAMPLE = Path(__file__).resolve().parent.parent / "examples" / "sample-retest"


def _json(name):
    return json.loads((SAMPLE / name).read_text(encoding="utf-8"))


def _yaml(name):
    return yaml.safe_load((SAMPLE / name).read_text(encoding="utf-8"))


def _list(page, name):
    match = re.search(rf'<ul class="{name}">(.*?)</ul>', page)
    return sorted(re.findall(r"<li>([a-z_]+:\d+)", match.group(1))) if match else []


def test_sample_retest_matches_its_inputs():
    page = render_customer_report(
        _json("retest.json"), _json("baseline.json"), engagement=_yaml("engagement.yaml"),
        triage=_yaml("triage.yaml"), baseline_triage=_yaml("baseline-triage.yaml"),
    )
    committed = (SAMPLE / "sample-retest.html").read_text(encoding="utf-8")
    assert page == committed, (
        "examples/sample-retest/sample-retest.html is stale; regenerate it with the "
        "command in examples/sample-retest/README.md"
    )


def test_sample_retest_shows_the_score_change_and_what_changed():
    page = (SAMPLE / "sample-retest.html").read_text(encoding="utf-8")
    assert '<p class="eyebrow">AI agent security retest report</p>' in page
    assert "<li>Baseline: <b>2026-10-24 (UTC), score 0</b></li>" in page
    assert '<span class="score">50<small> / 100 (+50 since baseline)</small></span>' in page
    assert '<span class="badge FAIL">FAIL</span>' in page
    assert _list(page, "fixed") == ["context_manipulation:2", "data_extraction:1",
                                    "data_extraction:4", "data_extraction:6",
                                    "indirect_injection:2", "role_confusion:1"]
    assert _list(page, "new") == ["context_manipulation:3", "jailbreak:6"]
    assert _list(page, "unchanged") == ["role_confusion:3", "role_confusion:6"]
    assert _list(page, "regressed") == [] and _list(page, "uncompared") == []
    assert (SAMPLE / "sample-retest.pdf").read_bytes().startswith(b"%PDF-")
