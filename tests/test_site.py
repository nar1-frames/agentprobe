"""The landing page stays a single self-contained file that renders from disk."""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PAGE = (ROOT / "site" / "index.html").read_text(encoding="utf-8")


def test_page_has_no_scripts_or_external_assets():
    lowered = PAGE.lower()
    for marker in ("<script", "<link", "<img", "<iframe", "@import", "url("):
        assert marker not in lowered, marker
    assert re.search(r'<meta name="viewport" content="width=device-width', PAGE)


def test_in_page_links_resolve():
    ids = set(re.findall(r'\sid="([^"]+)"', PAGE))
    for anchor in re.findall(r'href="#([^"]+)"', PAGE):
        assert anchor in ids, anchor


def test_offer_numbers_match_the_one_pager():
    offer = (ROOT / "offer" / "one-pager.md").read_text(encoding="utf-8")
    for fact in ("$2,500", "$6,000", "five business days", "within 30 days"):
        assert fact.lower() in offer.lower(), fact
        assert fact.lower() in PAGE.lower(), fact


def test_linked_repository_files_exist():
    repo = "https://github.com/nar1-frames/agentprobe/"
    for link in re.findall(r'href="(%s(?:blob|tree)/main/[^"]+)"' % re.escape(repo), PAGE):
        relative = link.split("/main/", 1)[1]
        assert (ROOT / relative).exists(), relative
    assert (ROOT / "examples" / "sample-report" / "sample-report.html").exists()
    assert (ROOT / "examples" / "sample-retest" / "sample-retest.html").exists()
