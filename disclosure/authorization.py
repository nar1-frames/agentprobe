# ============================================================
# AGENTPROBE v1.2 — AUTHORIZATION / SCOPE GUARD
# ============================================================
# The gate that stands in front of every scan against a target
# we do not own.
#
# Why this exists (the non-obvious part):
#   Most AI bug bounty programs — including OpenAI's Safety Bug
#   Bounty — run under Terms of Use that PROHIBIT automated or
#   programmatic extraction of model output and prohibit
#   circumventing rate limits. AgentProbe is, by definition, an
#   automated scanner. Pointing it at such a target's production
#   endpoint is a ToS violation, regardless of good intent.
#
#   So the responsible path for a third-party product is:
#     1. Discover a candidate on a model you control (v1.1 flow).
#     2. MANUALLY reproduce it against the product, within the
#        program's manual-testing rules.
#     3. Disclose via the program.
#
#   require_authorization() encodes exactly that. It refuses an
#   "automated" run unless the authorization record explicitly
#   permits automated testing, and refuses ANY run unless a human
#   has confirmed the engagement is authorized.
# ============================================================
import os
import glob
import yaml
from dataclasses import dataclass, field

# --- Scope classification of a finding -----------------------
PAYABLE = "PAYABLE"              # in-scope, meets the program's bar -> submit
INFORMATIONAL = "INFORMATIONAL"  # real impact but below the bar (e.g. repro rate)
OUT_OF_SCOPE = "OUT_OF_SCOPE"    # program does not pay for this class (e.g. jailbreaks)

# AgentProbe attack categories split by what bounty programs actually pay for.
# The 2026 paying programs reward attacker-controlled input crossing a trust
# boundary to drive an action or exfiltrate data. They explicitly exclude
# "the model said something bad" (generic jailbreaks, content-policy bypasses).
IMPACT_CLASS_CATEGORIES = {
    "indirect_injection",     # attacker text in ingested content hijacks the agent
    "tool_misuse",            # agent is driven to call a tool it shouldn't
    "privilege_escalation",   # agent crosses an intended permission boundary
    "data_extraction",        # exfiltration of another user's / the platform's data
}
CONTENT_CLASS_CATEGORIES = {
    "jailbreak",
    "role_confusion",
    "social_engineering",
    "context_manipulation",
}

# The two testing modes the gate understands.
MODE_AUTOMATED = "automated"  # AgentProbe fires prompts itself
MODE_MANUAL = "manual"        # a human reproduces a candidate by hand

DEFAULT_AUTH_DIR = os.path.join(os.path.dirname(__file__), "authorizations")


class AuthorizationError(Exception):
    """Raised when a scan is not permitted against a target."""


@dataclass
class Authorization:
    target_id: str
    program_name: str
    program_url: str
    platform: str                      # where reports are submitted (e.g. bugcrowd)
    in_scope: list = field(default_factory=list)
    out_of_scope: list = field(default_factory=list)
    automated_testing_permitted: bool = False
    min_reproducibility: float = 0.5   # program's repro bar; OpenAI's is 0.50
    test_account_required: bool = True
    safe_harbor: bool = False
    confirmed: bool = False            # a human has affirmed this engagement is authorized
    authorized_by: str = ""
    authorized_date: str = ""
    notes: str = ""
    raw: dict = field(default_factory=dict)


def load_authorization(path):
    """Parse a single authorization YAML file into an Authorization."""
    with open(path, "r") as f:
        data = yaml.safe_load(f) or {}
    scope = data.get("scope", {}) or {}
    rules = data.get("rules", {}) or {}
    auth = data.get("authorization", {}) or {}
    return Authorization(
        target_id=data.get("target_id", ""),
        program_name=data.get("program_name", ""),
        program_url=data.get("program_url", ""),
        platform=data.get("platform", ""),
        in_scope=scope.get("in_scope", []) or [],
        out_of_scope=scope.get("out_of_scope", []) or [],
        automated_testing_permitted=bool(rules.get("automated_testing_permitted", False)),
        min_reproducibility=float(rules.get("min_reproducibility", 0.5)),
        test_account_required=bool(rules.get("test_account_required", True)),
        safe_harbor=bool(rules.get("safe_harbor", False)),
        confirmed=bool(auth.get("confirmed", False)),
        authorized_by=auth.get("authorized_by", "") or "",
        authorized_date=auth.get("authorized_date", "") or "",
        notes=auth.get("notes", "") or "",
        raw=data,
    )


def find_authorization(target_id, auth_dir=DEFAULT_AUTH_DIR):
    """Locate the authorization file for a target_id, or return None."""
    if not os.path.isdir(auth_dir):
        return None
    for path in sorted(glob.glob(os.path.join(auth_dir, "*.yaml")) +
                       glob.glob(os.path.join(auth_dir, "*.yml"))):
        try:
            with open(path, "r") as f:
                data = yaml.safe_load(f) or {}
        except Exception:
            continue
        if data.get("target_id") == target_id:
            return path
    return None


def require_authorization(target_id, mode=MODE_AUTOMATED, auth_dir=DEFAULT_AUTH_DIR):
    """
    The gate. Return the Authorization if the scan is permitted; otherwise
    raise AuthorizationError with an actionable reason.

    Rules enforced, in order:
      1. An authorization record for target_id must exist.
      2. A human must have confirmed the engagement (confirmed: true).
      3. If mode is 'automated', the record must explicitly permit automated
         testing. If it doesn't, the caller is directed to the manual path.
    """
    path = find_authorization(target_id, auth_dir)
    if path is None:
        raise AuthorizationError(
            f"No authorization record for target '{target_id}'.\n"
            f"  Create one in {auth_dir}/ (see templates/authorization.example.yaml)\n"
            f"  and confirm you are permitted to test this target before scanning."
        )

    auth = load_authorization(path)

    if not auth.confirmed:
        raise AuthorizationError(
            f"Authorization for '{target_id}' is not confirmed.\n"
            f"  Set authorization.confirmed: true in {os.path.basename(path)} only after a\n"
            f"  human has verified the engagement is permitted by the program's rules.\n"
            f"  Program: {auth.program_name or '(unnamed)'} — {auth.program_url or '(no url)'}"
        )

    if mode == MODE_AUTOMATED and not auth.automated_testing_permitted:
        raise AuthorizationError(
            f"Automated scanning is NOT permitted against '{target_id}'.\n"
            f"  {auth.program_name or 'This program'} prohibits automated/programmatic testing.\n"
            f"  Responsible path: discover the candidate on a model you control, then\n"
            f"  reproduce MANUALLY within the program's rules, then disclose.\n"
            f"  Re-run with mode='{MODE_MANUAL}' to log a manual engagement instead."
        )

    return auth


def classify_finding(category, crossed_trust_boundary, reproducibility, auth):
    """
    Decide whether a finding is PAYABLE, INFORMATIONAL, or OUT_OF_SCOPE for a
    given program, using the criteria the 2026 programs actually apply.

    PAYABLE        impact-class category AND attacker input crossed a trust
                   boundary AND reproducibility meets the program's bar.
    INFORMATIONAL  real cross-boundary impact but below the repro bar — worth
                   tracking and possibly re-testing, not yet submittable.
    OUT_OF_SCOPE   content-class findings (jailbreaks, policy bypasses) or an
                   impact-class finding with no actual boundary crossing.
    """
    if category in IMPACT_CLASS_CATEGORIES and crossed_trust_boundary:
        if reproducibility >= auth.min_reproducibility:
            return PAYABLE
        return INFORMATIONAL
    return OUT_OF_SCOPE
