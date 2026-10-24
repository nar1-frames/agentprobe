"""Check every relative link in the tracked Markdown and HTML files.

A link is broken when the file or directory it points to is not tracked in Git,
or when its #fragment names a heading (Markdown) or id (HTML) the target does
not have. Links to this repository's own files on github.com
(``.../agentprobe/blob/main/<path>``, used where a page is also read off GitHub,
such as the README on PyPI) are checked the same way. Other external links are
not fetched. Links inside code blocks and inline code are ignored.

Usage: python scripts/check_links.py   (exit 1 and one line per broken link)
"""

import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parent.parent

# site/index.html is published by .github/workflows/pages.yml, which copies the
# samples next to it. Its links to those copies resolve to the repository files.
SITE_PATHS = {
    "site/sample-report/": "examples/sample-report/",
    "site/sample-retest/": "examples/sample-retest/",
}

_REPO_URL = re.compile(r"^https://github\.com/nar1-frames/agentprobe/(?:blob|tree)/main/(.*)$")
_EXTERNAL = re.compile(r"^(?:[a-z][a-z0-9+.-]*:|//)", re.IGNORECASE)
_FENCE = re.compile(r"^\s*(```|~~~)")
_INLINE_CODE = re.compile(r"(`+).+?\1")
_MD_LINK = re.compile(r"!?\[(?:[^\[\]]|\[[^\]]*\])*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
_MD_REF = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s+\"[^\"]*\")?\s*$")
_HTML_ATTR = re.compile(r"""\s(?:href|src)\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_HTML_ID = re.compile(r"""\s(?:id|name)\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_HEADING = re.compile(r"^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$")


def tracked(root=ROOT):
    out = subprocess.run(["git", "ls-files", "-z"], cwd=root, check=True,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    return {raw.decode("utf-8") for raw in out.split(b"\0") if raw}


def _prose_lines(text, strip_inline_code=True):
    """Yield (line number, line) outside fenced code, by default with inline code removed."""
    fenced = None
    for number, line in enumerate(text.splitlines(), 1):
        fence = _FENCE.match(line)
        if fence:
            fenced = None if fenced == fence.group(1) else (fenced or fence.group(1))
            continue
        if fenced is None:
            yield number, _INLINE_CODE.sub("", line) if strip_inline_code else line


def _slug(heading):
    """GitHub's heading anchor: lowercase, punctuation dropped, spaces to hyphens."""
    heading = re.sub(r"<[^>]+>", "", heading)
    heading = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    heading = heading.strip().lower()
    heading = re.sub(r"[^\w\- ]", "", heading)
    return heading.replace(" ", "-")


def anchors(path):
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() in (".html", ".htm"):
        return set(_HTML_ID.findall(text))
    seen, found = {}, set(_HTML_ID.findall(text))
    # GitHub keeps the text of inline code in a heading's anchor.
    for _, line in _prose_lines(text, strip_inline_code=False):
        match = _HEADING.match(line)
        if match:
            slug = _slug(match.group(2))
            count = seen.get(slug, 0)
            seen[slug] = count + 1
            found.add(slug if count == 0 else f"{slug}-{count}")
    return found


def links(path):
    """Yield (line number, link target) for every link in a Markdown or HTML file."""
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() in (".html", ".htm"):
        for number, line in enumerate(text.splitlines(), 1):
            for target in _HTML_ATTR.findall(line):
                yield number, target
        return
    for number, line in _prose_lines(text):
        for target in _MD_LINK.findall(line):
            yield number, target
        ref = _MD_REF.match(line)
        if ref:
            yield number, ref.group(1)
        for target in _HTML_ATTR.findall(line):
            yield number, target


def _resolve(source, target_path, files, dirs):
    joined = PurePosixPath(source).parent / target_path
    parts = []
    for part in joined.parts:
        if part == "..":
            if not parts:
                return None
            parts.pop()
        elif part != ".":
            parts.append(part)
    resolved = "/".join(parts)
    for published, repo in SITE_PATHS.items():
        if resolved.startswith(published):
            resolved = repo + resolved[len(published):]
    if resolved in files or resolved.rstrip("/") in dirs or resolved == "":
        return resolved
    return None


def check(root=ROOT, files=None):
    """Return one line per broken link; ``files`` defaults to the Git index."""
    files = tracked(root) if files is None else set(files)
    dirs = {str(PurePosixPath(f).parent) for f in files}
    dirs |= {str(p) for f in files for p in PurePosixPath(f).parents}
    problems = []
    cache = {}
    for source in sorted(f for f in files if f.lower().endswith((".md", ".html", ".htm"))):
        for number, raw in links(root / source):
            target = unquote(raw.strip())
            base = source
            repo = _REPO_URL.match(target)
            if repo:
                target, base = repo.group(1), "README.md"
            if not target or (not repo and _EXTERNAL.match(target)):
                continue
            path_part, _, fragment = target.partition("#")
            path_part = path_part.split("?", 1)[0]
            if path_part.startswith("/"):
                problems.append(f"{source}:{number}: {raw} (root-relative links do not "
                                "resolve on GitHub and PyPI)")
                continue
            resolved = _resolve(base, path_part, files, dirs) if path_part else source
            if resolved is None:
                problems.append(f"{source}:{number}: {raw} (no such tracked file)")
                continue
            if fragment and resolved in files and resolved.lower().endswith(
                    (".md", ".html", ".htm")):
                if resolved not in cache:
                    cache[resolved] = anchors(root / resolved)
                if fragment not in cache[resolved]:
                    problems.append(f"{source}:{number}: {raw} (no anchor #{fragment})")
    return problems


def main():
    problems = check()
    for problem in problems:
        print(problem)
    print(f"{len(problems)} broken relative link(s)" if problems else "All relative links resolve.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
