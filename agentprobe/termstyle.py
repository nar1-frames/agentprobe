"""Shared plain-ASCII terminal presentation helpers.

Every surface that prints to a terminal (the harness, the verbose scanner, and
``agentprobe compare``) uses the same fixed-width status tags so a first-time
reader sees one vocabulary. Output is ASCII only so CI logs and Windows cp1252
consoles stay clean; ANSI colour is layered on only for an interactive terminal.

This module imports nothing from ``agentprobe`` so any module may use it
without creating an import cycle.

Colour gating: ``colour_enabled()`` is true only when stdout is a TTY, the
``NO_COLOR`` variable is unset, ``TERM`` is not ``dumb``, and nobody has called
``configure(no_color=True)``. The CLI calls ``configure`` once from its
``--no-color`` flag so library code (the scanner) never reads argparse.
"""

from __future__ import annotations

import os
import sys
from typing import Any
from typing import Optional

# Harness tags.
TAG_BLOCKED = "[BLOCKED]"
TAG_ATTACK_OK = "[ATTACK OK]"
TAG_CONTROL_OK = "[CONTROL OK]"
TAG_CONTROL_FAIL = "[CONTROL FAIL]"
TAG_ERROR = "[ERROR]"
# Scan verdict tags.
TAG_VULNERABLE = "[VULNERABLE]"
TAG_PARTIAL = "[PARTIAL]"
TAG_SUSPICIOUS = "[SUSPICIOUS]"
TAG_SAFE = "[SAFE]"
# Compare tags (legend vocabulary; see compare.format_comparison_text).
TAG_REGRESSED = "[REGRESSED]"
TAG_NEW_ERROR = "[NEW ERROR]"
TAG_ADDED = "[ADDED]"
TAG_REMOVED = "[REMOVED]"

_ALL_TAGS = (
    TAG_BLOCKED, TAG_ATTACK_OK, TAG_CONTROL_OK, TAG_CONTROL_FAIL, TAG_ERROR,
    TAG_VULNERABLE, TAG_PARTIAL, TAG_SUSPICIOUS, TAG_SAFE,
    TAG_REGRESSED, TAG_NEW_ERROR, TAG_ADDED, TAG_REMOVED,
)
TAG_WIDTH = max(map(len, _ALL_TAGS))
# Continuation lines under a tagged line start here.
INDENT = " " * (TAG_WIDTH + 2)

_VERDICT_TAGS = {
    "VULNERABLE": TAG_VULNERABLE,
    "PARTIAL": TAG_PARTIAL,
    "SUSPICIOUS": TAG_SUSPICIOUS,
    "SAFE": TAG_SAFE,
}
_ERROR_METHODS = frozenset({"target-error", "judge-error"})

_ANSI = {"green": "\x1b[32m", "red": "\x1b[31m", "yellow": "\x1b[33m", "reset": "\x1b[0m"}
_TAG_COLOURS = {
    TAG_BLOCKED: "green",
    TAG_CONTROL_OK: "green",
    TAG_SAFE: "green",
    TAG_ATTACK_OK: "red",
    TAG_CONTROL_FAIL: "red",
    TAG_VULNERABLE: "red",
    TAG_REGRESSED: "red",
    TAG_ERROR: "yellow",
    TAG_PARTIAL: "yellow",
    TAG_SUSPICIOUS: "yellow",
    TAG_NEW_ERROR: "yellow",
}

_forced_off = False


def configure(no_color: bool) -> None:
    """Record the CLI's --no-color choice for every later ``style`` call."""
    global _forced_off
    _forced_off = bool(no_color)


def colour_enabled(no_color: bool = False) -> bool:
    """ANSI colour only on an interactive terminal that has not opted out."""
    if no_color or _forced_off:
        return False
    if os.environ.get("NO_COLOR") is not None or os.environ.get("TERM") == "dumb":
        return False
    try:
        return bool(sys.stdout.isatty())
    except (AttributeError, ValueError):
        return False


def style(tag: str, colour: Optional[bool] = None) -> str:
    """Return a fixed-width status tag, wrapped in ANSI colour when enabled.

    The visible text is identical with or without colour so log greps and
    tests can match the tag token either way.
    """
    padded = tag.ljust(TAG_WIDTH)
    if colour is None:
        colour = colour_enabled()
    if not colour:
        return padded
    name = _TAG_COLOURS.get(tag)
    if name is None:
        return padded
    return f"{_ANSI[name]}{padded}{_ANSI['reset']}"


def console_is_unicode(stream: Any = None) -> bool:
    """True when the console can render non-ASCII glyphs (a UTF encoding).

    Windows consoles often report ``cp1252``; there emoji and em dashes print
    as ``?`` and the caller should use the ASCII tags instead.
    """
    encoding = getattr(stream if stream is not None else sys.stdout, "encoding", None) or ""
    return "utf" in encoding.lower()


def glyph(unicode_text: str, ascii_text: str) -> str:
    """Return ``unicode_text`` on a UTF console, otherwise ``ascii_text``."""
    return unicode_text if console_is_unicode() else ascii_text


def print_scan_summary(report: Any) -> None:
    """Print the plain four-line verdict summary of a scan report, if it has one.

    Shared by the non-interactive CLI path and the interactive runner so the
    block appears exactly once, in the same shape, before the saved-file lines.
    """
    summary = report.get("summary") if isinstance(report, dict) else None
    if not summary:
        return
    print(
        f"Scan summary: {summary.get('total_attacks', 0)} attacks "
        f"({summary.get('scorable_attacks', 0)} scorable), "
        f"{summary.get('operational_errors', 0)} operational errors"
    )
    verdicts = summary.get("verdicts", {})
    print("Verdicts: " + ", ".join(f"{name} {count}" for name, count in verdicts.items()))
    severities = [
        f"{name} {count}"
        for name, count in summary.get("findings_by_severity", {}).items()
        if count
    ]
    print("Findings by severity: " + (", ".join(severities) if severities else "none"))
    print("Verdict key: SAFE refused, SUSPICIOUS unclear, PARTIAL hedged then complied, "
          "VULNERABLE complied")


def verdict_tag(verdict: str, method: Optional[str] = None) -> str:
    """Map a scan verdict (and the method that produced it) to a status tag.

    An operational failure is never a verdict, so ``target-error`` and
    ``judge-error`` rows are tagged ``[ERROR]`` whatever verdict text they carry.
    """
    if method in _ERROR_METHODS:
        return TAG_ERROR
    return _VERDICT_TAGS.get(str(verdict), "[?]")
