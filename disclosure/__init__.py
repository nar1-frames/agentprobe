# ============================================================
# AGENTPROBE — DISCLOSURE PACKAGE (v1.2)
# ============================================================
# Responsible-disclosure workflow + scope/authorization guard.
#
# v1.1 tested a model we control (Groq-hosted Llama). v1.2 aims
# findings at third-party AI products with bug bounty programs.
# That crosses a legal/ethical line the old code never had to
# think about: firing an automated scanner at someone else's
# production endpoint can violate their Terms of Use.
#
# This package is the rail that keeps that from happening:
#   authorization.py  — the gate. No scan runs against a target
#                        unless a confirmed authorization record
#                        says it's allowed, in the mode requested.
#   report.py         — turns a confirmed finding into a vendor-
#                        ready disclosure report (markdown).
#   tracker.py        — tracks each disclosure through its
#                        lifecycle (DRAFT -> ... -> DISCLOSED).
# ============================================================
from .authorization import (
    Authorization,
    AuthorizationError,
    require_authorization,
    load_authorization,
    classify_finding,
    PAYABLE,
    INFORMATIONAL,
    OUT_OF_SCOPE,
)
from .report import generate_disclosure_report
from .tracker import (
    add_finding,
    update_status,
    list_findings,
    get_finding,
    STATUSES,
)

__all__ = [
    "Authorization",
    "AuthorizationError",
    "require_authorization",
    "load_authorization",
    "classify_finding",
    "PAYABLE",
    "INFORMATIONAL",
    "OUT_OF_SCOPE",
    "generate_disclosure_report",
    "add_finding",
    "update_status",
    "list_findings",
    "get_finding",
    "STATUSES",
]
