# ============================================================
# AGENTPROBE v1.2 — DISCLOSURE TRACKER
# ============================================================
# A tiny JSON-backed ledger for responsible disclosure. Each
# confirmed finding moves through a lifecycle; the tracker is the
# single source of truth for "what have we reported, and where is
# it now" across multiple findings and programs.
#
# The ledger lives under disclosure/data/ and is gitignored — it
# names real targets and unpatched vulnerabilities, so it stays
# local, exactly like reports/.
# ============================================================
import os
import json
import glob

# Lifecycle. A finding starts as DRAFT and ends DISCLOSED (public,
# post-fix) or in one of the terminal triage states.
STATUSES = [
    "DRAFT",           # written up, not yet sent
    "SUBMITTED",       # sent to the program
    "TRIAGED",         # program acknowledged / is reviewing
    "ACCEPTED",        # confirmed valid (bounty pending/paid)
    "DUPLICATE",       # already known to the vendor
    "NOT_APPLICABLE",  # vendor ruled out of scope / not a vuln
    "RESOLVED",        # vendor shipped a fix
    "DISCLOSED",       # published, after embargo
]

TERMINAL_STATUSES = {"DUPLICATE", "NOT_APPLICABLE", "DISCLOSED"}

DEFAULT_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
DEFAULT_TRACKER_PATH = os.path.join(DEFAULT_DATA_DIR, "tracker.json")


def _load(path=DEFAULT_TRACKER_PATH):
    if not os.path.exists(path):
        return {"findings": []}
    with open(path, "r") as f:
        return json.load(f)


def _save(data, path=DEFAULT_TRACKER_PATH):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def _next_id(data, target_id):
    """Stable, human-readable id: <target>-NNN, monotonic per target."""
    n = sum(1 for f in data["findings"] if f.get("target_id") == target_id) + 1
    return f"{target_id}-{n:03d}"


def add_finding(target_id, title, category, classification, severity,
                discovered_date, reproducibility=None, note="",
                path=DEFAULT_TRACKER_PATH):
    """Register a new finding at DRAFT. Returns the assigned finding id."""
    data = _load(path)
    finding_id = _next_id(data, target_id)
    record = {
        "id": finding_id,
        "target_id": target_id,
        "title": title,
        "category": category,
        "classification": classification,
        "severity": severity,
        "reproducibility": reproducibility,
        "discovered_date": discovered_date,
        "status": "DRAFT",
        "history": [{"status": "DRAFT", "date": discovered_date, "note": note}],
    }
    data["findings"].append(record)
    _save(data, path)
    return finding_id


def update_status(finding_id, status, date, note="", bounty=None,
                  path=DEFAULT_TRACKER_PATH):
    """Advance a finding to a new lifecycle status. Returns the updated record."""
    if status not in STATUSES:
        raise ValueError(f"Unknown status '{status}'. One of: {', '.join(STATUSES)}")
    data = _load(path)
    for record in data["findings"]:
        if record["id"] == finding_id:
            record["status"] = status
            if bounty is not None:
                record["bounty"] = bounty
            record.setdefault("history", []).append(
                {"status": status, "date": date, "note": note}
            )
            _save(data, path)
            return record
    raise KeyError(f"No finding with id '{finding_id}'")


def get_finding(finding_id, path=DEFAULT_TRACKER_PATH):
    for record in _load(path)["findings"]:
        if record["id"] == finding_id:
            return record
    return None


def list_findings(target_id=None, status=None, path=DEFAULT_TRACKER_PATH):
    """Return findings, optionally filtered by target and/or status."""
    findings = _load(path)["findings"]
    if target_id:
        findings = [f for f in findings if f.get("target_id") == target_id]
    if status:
        findings = [f for f in findings if f.get("status") == status]
    return findings
