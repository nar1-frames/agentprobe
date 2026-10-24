"""The committed sample report is exactly what the code renders from its inputs."""

import json
from pathlib import Path

import yaml

from agentprobe.customer_report import render_customer_report


SAMPLE = Path(__file__).resolve().parent.parent / "examples" / "sample-report"


def _load_yaml(name):
    return yaml.safe_load((SAMPLE / name).read_text(encoding="utf-8"))


def test_sample_report_matches_its_inputs():
    scan = json.loads((SAMPLE / "scan.json").read_text(encoding="utf-8"))
    page = render_customer_report(scan, engagement=_load_yaml("engagement.yaml"),
                                  triage=_load_yaml("triage.yaml"))
    committed = (SAMPLE / "sample-report.html").read_text(encoding="utf-8")
    assert page == committed, (
        "examples/sample-report/sample-report.html is stale; regenerate it with the "
        "command in examples/sample-report/README.md"
    )


def test_sample_report_shows_the_reviewed_public_scan():
    page = (SAMPLE / "sample-report.html").read_text(encoding="utf-8")
    assert "Prepared by: <b>Naren Ranjith</b>" in page
    assert '<span class="badge FAIL">FAIL</span>' in page
    assert "set aside 3 as false positives" in page
    for attack_id in ("data_extraction:8", "social_engineering:1", "tool_misuse:4"):
        aside = page[page.index('id="set-aside"'):page.index('id="method"')]
        assert attack_id in aside
    # The two disclosures the judge scored SAFE (public-scan-01 correction) are added back.
    assert "The analyst also added 2 findings" in page
    findings = page[page.index('id="findings"'):page.index('id="categories"')]
    for attack_id in ("data_extraction:1", "indirect_injection:2"):
        assert f"({attack_id})</span> <span class=\"id\">(added by the analyst)</span>" in findings
    assert '<span class="score">0<small> / 100</small></span>' in page
    assert (SAMPLE / "sample-report.pdf").read_bytes().startswith(b"%PDF-")
