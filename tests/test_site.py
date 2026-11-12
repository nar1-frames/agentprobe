"""The landing page and its legal and intake pages stay consistent and linkable.

The pages under site/ are published as they are by .github/workflows/pages.yml,
which also copies the sample report and retest beside them.
"""

import re
from pathlib import Path, PurePosixPath
from urllib.parse import unquote

import pytest


ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
PAGES = ("index.html", "privacy.html", "terms.html", "order-received.html")
REPO_URL = "https://github.com/nar1-frames/agentprobe/"
# Folders the Pages workflow copies in next to the pages.
PUBLISHED_COPIES = {
    "sample-report": ROOT / "examples" / "sample-report",
    "sample-retest": ROOT / "examples" / "sample-retest",
}

_ATTR = re.compile(r"""\s(?:href|src)\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
_CSS_URL = re.compile(r"""url\(\s*["']?([^"')]+)["']?\s*\)""", re.IGNORECASE)
_ID = re.compile(r"""\sid\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_SCHEME = re.compile(r"^(?:[a-z][a-z0-9+.-]*:|//)", re.IGNORECASE)


def read(page):
    return (SITE / page).read_text(encoding="utf-8")


def references(html):
    return _ATTR.findall(html) + _CSS_URL.findall(html)


def ids(html):
    return set(_ID.findall(html))


def published_file(name):
    """Map a path relative to site/ to the file the deployed site would serve."""
    parts = PurePosixPath(name).parts
    if parts and parts[0] in PUBLISHED_COPIES:
        return PUBLISHED_COPIES[parts[0]].joinpath(*parts[1:])
    return SITE.joinpath(*parts)


@pytest.mark.parametrize("page", PAGES)
def test_local_links_and_files_resolve(page):
    html = read(page)
    for raw in references(html):
        target = unquote(raw.strip())
        if target.startswith(REPO_URL):
            relative = re.sub(r"^(?:blob|tree)/main/", "", target[len(REPO_URL):])
            relative = relative.split("#", 1)[0]
            if relative:
                assert (ROOT / relative).exists(), f"{page}: {raw}"
            continue
        if not target or target == "#" or _SCHEME.match(target):
            continue
        path, _, fragment = target.partition("#")
        path = path.split("?", 1)[0]
        assert not path.startswith("/"), f"{page}: {raw} is root-relative"
        if not path:
            assert fragment in ids(html), f"{page}: {raw}"
            continue
        resolved = published_file(path)
        assert resolved.exists(), f"{page}: {raw}"
        if fragment and resolved.suffix == ".html":
            assert fragment in ids(resolved.read_text(encoding="utf-8")), f"{page}: {raw}"


@pytest.mark.parametrize("page", PAGES)
def test_no_contact_placeholder(page):
    assert "CONTACT_EMAIL" not in read(page)


def test_index_has_checkout_setting_and_three_buttons():
    html = read("index.html")
    assert re.search(r"""\bvar\s+CHECKOUT_URL\s*=\s*["'][^"']*["']""", html)
    buttons = re.findall(r"<a\b[^>]*\sdata-checkout(?=[\s>=])[^>]*>", html)
    assert len(buttons) == 3, buttons


def test_index_links_privacy_and_terms():
    linked = set(_ATTR.findall(read("index.html")))
    assert "privacy.html" in linked
    assert "terms.html" in linked
