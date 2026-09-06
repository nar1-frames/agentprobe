"""Fail-closed checks for the public repository surface.

The working tree may contain local reports, credentials, disclosure records,
and recovery copies. By default this check inspects only paths in the Git
index, because that is what a public checkout contains. A pre-commit caller
can opt into non-ignored untracked files as well. Test fixtures are allowed to
contain obviously fake key-shaped strings; production data and documentation
are not.
"""

import argparse
import re
import subprocess
import zipfile
from pathlib import Path


_FORBIDDEN_PARTS = frozenset({
    ".git", ".venv", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", "reports", "dist", "disclosure/data",
})
_FORBIDDEN_NAMES = frozenset({
    ".env", "mysession.txt", "report_html.py",
    "agentprobe-backup-preconsolidation", "_variants_from_B",
    "judgements_clean.jsonl", "judgements_errors_pilot.jsonl", "results_pilot.json",
})
_SECRET_PATTERNS = (
    ("provider-key", re.compile(rb"(?i)\b(?:sk|gsk)[_-][A-Za-z0-9_-]{12,}\b")),
    ("github-token", re.compile(rb"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("slack-token", re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("tenant-id", re.compile(rb"\borg_[A-Za-z0-9_-]{8,}\b")),
    ("private-key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
)


def tracked_files(root="."):
    """Return paths currently tracked by Git, not merely present on disk."""

    result = subprocess.run(
        ["git", "ls-files", "-z"], cwd=root, check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return [Path(raw.decode("utf-8")) for raw in result.stdout.split(b"\0") if raw]


def untracked_files(root="."):
    """Return non-ignored files not yet in the Git index."""

    result = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return [Path(raw.decode("utf-8")) for raw in result.stdout.split(b"\0") if raw]


def _forbidden_path(relative_path):
    relative_path = Path(relative_path)
    parts = set(relative_path.parts)
    if parts & _FORBIDDEN_PARTS:
        return True
    if relative_path.parts[:2] == ("disclosure", "data"):
        return True
    if any(part in _FORBIDDEN_NAMES for part in relative_path.parts):
        return True
    if relative_path.name.endswith(".errors.jsonl"):
        return True
    if relative_path.name.endswith((".checkpoint.json", ".checkpoint.jsonl")):
        return True
    if relative_path.name.startswith(".env"):
        return True
    if re.search(r" 2\.[^/]+$", relative_path.name):
        return True
    if relative_path.parts[:2] == ("disclosure", "authorizations"):
        return relative_path.suffix.lower() in {".yaml", ".yml"}
    return False


def scan_content(relative_path, content, allow_test_fixtures=True):
    """Return non-sensitive hygiene findings for one tracked file."""

    findings = []
    relative_path = Path(relative_path)
    if _forbidden_path(relative_path):
        findings.append(f"{relative_path}: forbidden generated/private path")
    if allow_test_fixtures and relative_path.parts and relative_path.parts[0] == "tests":
        return findings
    for label, pattern in _SECRET_PATTERNS:
        if pattern.search(content):
            findings.append(f"{relative_path}: credential-like {label} pattern")
    return findings


def scan_public_tree(root=".", include_untracked=False):
    """Inspect public candidate files without exposing secret matches."""

    findings = []
    root = Path(root)
    paths = tracked_files(str(root))
    if include_untracked:
        paths += untracked_files(str(root))
    for relative_path in paths:
        absolute_path = root / relative_path
        try:
            content = absolute_path.read_bytes()
        except OSError as exc:
            findings.append(f"{relative_path}: cannot read tracked file ({exc})")
            continue
        findings.extend(scan_content(relative_path, content))
    return findings


def scan_wheel(path):
    """Check a built wheel for local backups, caches, or duplicate artifacts."""

    findings = []
    try:
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                relative = Path(name)
                if ("agentprobe-backup-preconsolidation" in relative.parts
                        or "_variants_from_B" in relative.parts
                        or any(part in {".git", "__pycache__", ".pytest_cache"}
                               for part in relative.parts)
                        or re.search(r" 2\.[^/]+$", relative.name)):
                    findings.append(f"{name}: forbidden wheel artifact")
    except (OSError, zipfile.BadZipFile) as exc:
        findings.append(f"{path}: cannot inspect wheel ({exc})")
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check the tracked public repository surface")
    parser.add_argument("--root", default=".", help="Git worktree to inspect")
    parser.add_argument(
        "--include-untracked", action="store_true",
        help="also inspect non-ignored files not yet in the Git index",
    )
    parser.add_argument(
        "--wheel", default=None,
        help="also inspect a built wheel for backup, cache, and duplicate artifacts",
    )
    args = parser.parse_args(argv)
    try:
        findings = scan_public_tree(args.root, include_untracked=args.include_untracked)
        if args.wheel:
            findings.extend(scan_wheel(args.wheel))
    except (OSError, subprocess.CalledProcessError, UnicodeError) as exc:
        parser.error(f"could not inspect tracked files: {exc}")
    if findings:
        print("PUBLIC TREE NOT READY")
        for finding in findings:
            print(f"BLOCKED: {finding}")
        return 1
    print("PUBLIC TREE OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
