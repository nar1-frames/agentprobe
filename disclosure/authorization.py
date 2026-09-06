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
import math
from datetime import date
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


def _strict_bool(value, name, default):
    """Accept YAML booleans only; never treat a string as truthy permission."""

    if value is None:
        return default
    if not isinstance(value, bool):
        raise AuthorizationError(f"{name} must be a YAML boolean (true or false)")
    return value


def _required_string(value, name):
    if not isinstance(value, str) or not value.strip():
        raise AuthorizationError(f"{name} must be a non-empty string")
    return value.strip()


def _scope_list(value, name):
    if value is None:
        return []
    if not isinstance(value, list):
        raise AuthorizationError(f"{name} must be a list")
    return value


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
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise AuthorizationError(f"Could not read authorization record {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise AuthorizationError("authorization record must be a YAML mapping")
    try:
        scope = data.get("scope", {}) or {}
        rules = data.get("rules", {}) or {}
        auth = data.get("authorization", {}) or {}
        if not isinstance(scope, dict) or not isinstance(rules, dict) or not isinstance(auth, dict):
            raise AuthorizationError("scope, rules, and authorization must be YAML mappings")
        target_id = _required_string(data.get("target_id"), "target_id")
        program_name = _required_string(data.get("program_name"), "program_name")
        program_url = _required_string(data.get("program_url"), "program_url")
        platform = _required_string(data.get("platform"), "platform")
        min_reproducibility = float(rules.get("min_reproducibility", 0.5))
        if not math.isfinite(min_reproducibility) or not 0 <= min_reproducibility <= 1:
            raise AuthorizationError("rules.min_reproducibility must be between 0 and 1")
        authorized_by = auth.get("authorized_by", "") or ""
        authorized_date = auth.get("authorized_date", "") or ""
        if not isinstance(authorized_by, str):
            raise AuthorizationError("authorization.authorized_by must be a string")
        if isinstance(authorized_date, date):
            authorized_date = authorized_date.isoformat()
        elif not isinstance(authorized_date, str):
            raise AuthorizationError(
                "authorization.authorized_date must be an ISO date string"
            )
        confirmed = _strict_bool(auth.get("confirmed"), "authorization.confirmed", False)
        if confirmed and (not authorized_by.strip() or not authorized_date.strip()):
            raise AuthorizationError(
                "confirmed authorization requires authorization.authorized_by and "
                "authorization.authorized_date"
            )
    except (TypeError, ValueError) as exc:
        raise AuthorizationError(f"Invalid authorization record {path}: {exc}") from exc
    return Authorization(
        target_id=target_id,
        program_name=program_name,
        program_url=program_url,
        platform=platform,
        in_scope=_scope_list(scope.get("in_scope"), "scope.in_scope"),
        out_of_scope=_scope_list(scope.get("out_of_scope"), "scope.out_of_scope"),
        automated_testing_permitted=_strict_bool(
            rules.get("automated_testing_permitted"),
            "rules.automated_testing_permitted", False,
        ),
        min_reproducibility=min_reproducibility,
        test_account_required=_strict_bool(
            rules.get("test_account_required"), "rules.test_account_required", True
        ),
        safe_harbor=_strict_bool(rules.get("safe_harbor"), "rules.safe_harbor", False),
        confirmed=confirmed,
        authorized_by=authorized_by.strip(),
        authorized_date=authorized_date.strip(),
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
    if not isinstance(target_id, str) or not target_id.strip():
        raise AuthorizationError("target_id must be a non-empty string")
    if mode not in {MODE_AUTOMATED, MODE_MANUAL}:
        raise AuthorizationError(
            f"Unknown testing mode '{mode}'. Use '{MODE_AUTOMATED}' or '{MODE_MANUAL}'."
        )

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
    try:
        reproducibility = float(reproducibility)
    except (TypeError, ValueError) as exc:
        raise ValueError("reproducibility must be numeric") from exc
    if not math.isfinite(reproducibility) or not 0 <= reproducibility <= 1:
        raise ValueError("reproducibility must be between 0 and 1")
    if category in IMPACT_CLASS_CATEGORIES and crossed_trust_boundary is True:
        if reproducibility >= auth.min_reproducibility:
            return PAYABLE
        return INFORMATIONAL
    return OUT_OF_SCOPE
