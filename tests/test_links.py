"""Every relative link in the repository resolves, and the docs index is complete."""

import importlib.util
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("check_links", ROOT / "scripts" / "check_links.py")
check_links = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_links)


def test_every_relative_link_in_the_repository_resolves():
    assert check_links.check() == []


def _write(root, files):
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return set(files)


def test_broken_paths_and_anchors_are_reported(tmp_path):
    files = _write(tmp_path, {
        "README.md": (
            "[ok](docs/A.md#usage) [missing](docs/B.md) [bad anchor](docs/A.md#nope)\n"
            "[repo ok](https://github.com/nar1-frames/agentprobe/blob/main/docs/A.md)\n"
            "[repo missing](https://github.com/nar1-frames/agentprobe/blob/main/docs/C.md)\n"
            "[external](https://example.com/x.md) `[in code](nowhere.md)`\n"
            "```\n[fenced](nowhere.md)\n```\n"
        ),
        "docs/A.md": ("# Title\n\n## Usage\n\n## The `http` target\n\n"
                      "[up](../README.md) [self](#title) [code](#the-http-target)\n"),
        "site/index.html": '<a href="sample-report/r.html">r</a> <a href="#x">x</a><p id="x"></p>',
        "examples/sample-report/r.html": "<p>report</p>",
    })
    problems = check_links.check(tmp_path, files)
    assert len(problems) == 3, problems
    assert any("docs/B.md (no such tracked file)" in p for p in problems)
    assert any("docs/A.md#nope (no anchor #nope)" in p for p in problems)
    assert any("docs/C.md (no such tracked file)" in p for p in problems)


def test_heading_slugs_match_github():
    assert check_links._slug("Scan your own agent") == "scan-your-own-agent"
    assert check_links._slug("60-second demo") == "60-second-demo"
    assert check_links._slug("Reports and retests") == "reports-and-retests"
    assert check_links._slug("A deployed agent: `http`") == "a-deployed-agent-http"
    assert check_links._slug("The research question: *can we trust the judge?*") == (
        "the-research-question-can-we-trust-the-judge")


# writeups/ keeps drafts; only its index and the published write-ups are documents.
_PUBLISHED_WRITEUPS = {"writeups/README.md", "writeups/public-scan-01.md", "writeups/benchmark-01.md"}


def _is_document(name):
    if not name.endswith(".md") or name in {"README.md", "docs/README.md"}:
        return False
    if name.startswith(".github/"):
        return False
    return not name.startswith("writeups/") or name in _PUBLISHED_WRITEUPS


def test_docs_index_lists_every_document():
    index = (ROOT / "docs" / "README.md").read_text(encoding="utf-8")
    listed = {
        (ROOT / "docs" / target).resolve().relative_to(ROOT).as_posix()
        for target in re.findall(r"\]\(([^)#]+\.md)\)", index)
    }
    missing = sorted(name for name in check_links.tracked()
                     if _is_document(name) and name not in listed)
    assert not missing, f"add these to docs/README.md: {missing}"
