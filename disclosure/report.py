# ============================================================
# AGENTPROBE v1.2 — DISCLOSURE REPORT GENERATOR
# ============================================================
# Turns a confirmed finding into a vendor-ready disclosure report
# (markdown). The template is built around what the 2026 programs
# actually grade on: a reproducible, cross-trust-boundary impact —
# NOT "the model said something bad".
#
# The report leads with the scope classification so a triager sees
# immediately why this is (or isn't) payable, then gives everything
# needed to reproduce: the exact payload, the agent/tool config it
# ran under, the observed harmful action, and the repro rate.
# ============================================================
from .authorization import PAYABLE, INFORMATIONAL, OUT_OF_SCOPE

# A finding dict is expected to carry these keys (missing ones degrade
# gracefully to a "[TODO: ...]" placeholder so the draft is still usable):
_PLACEHOLDER = "[TODO: fill in before submitting]"


def _get(finding, key, default=None):
    val = finding.get(key)
    if val in (None, ""):
        return default if default is not None else _PLACEHOLDER
    return val


def _repro_line(finding, auth):
    runs_total = finding.get("runs_total")
    runs_ok = finding.get("runs_reproduced")
    rate = finding.get("reproducibility")
    if runs_total and runs_ok is not None:
        rate = runs_ok / runs_total
        detail = f"{runs_ok}/{runs_total} runs ({rate:.0%})"
    elif rate is not None:
        detail = f"{rate:.0%}"
    else:
        return _PLACEHOLDER
    bar = auth.min_reproducibility
    verdict = "meets" if rate >= bar else "BELOW"
    return f"{detail} — {verdict} the program bar of {bar:.0%}"


def _classification_note(classification):
    return {
        PAYABLE: "In scope and meets the program's bar — submit.",
        INFORMATIONAL: "Real cross-boundary impact but below the reproducibility "
                       "bar. Track and re-test; not yet submittable.",
        OUT_OF_SCOPE: "Out of scope for this program (content-class finding or no "
                      "trust-boundary crossing). Do NOT submit — informational only.",
    }.get(classification, "Unclassified.")


def generate_disclosure_report(finding, auth, reporter_handle="nar1"):
    """
    Build a markdown disclosure report from a finding dict and an
    Authorization. Safe to call on an incomplete finding — unknown fields
    render as explicit TODOs so nothing silently ships blank.
    """
    classification = finding.get("classification", OUT_OF_SCOPE)
    title = _get(finding, "title")

    lines = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"**Program:** {auth.program_name or _PLACEHOLDER}  ")
    lines.append(f"**Submit via:** {auth.platform or _PLACEHOLDER}  ")
    lines.append(f"**Reporter:** {reporter_handle}  ")
    lines.append(f"**Discovered:** {_get(finding, 'discovered_date')}  ")
    lines.append(f"**Category:** {_get(finding, 'category')}  ")
    lines.append(f"**Severity:** {_get(finding, 'severity')}")
    lines.append("")

    # Scope classification up top — the first thing a triager needs.
    lines.append(f"## Scope classification: {classification}")
    lines.append("")
    lines.append(_classification_note(classification))
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(_get(finding, "summary"))
    lines.append("")

    lines.append("## Affected target")
    lines.append("")
    lines.append(f"- **Product / model:** {_get(finding, 'target_product')}")
    lines.append(f"- **Version / snapshot:** {_get(finding, 'target_version')}")
    lines.append(f"- **Surface:** {_get(finding, 'surface', 'agent with tool access')}")
    lines.append("")

    lines.append("## Reproduction")
    lines.append("")
    lines.append("**Agent / tool configuration:**")
    lines.append("")
    lines.append("```")
    lines.append(str(_get(finding, "agent_config")))
    lines.append("```")
    lines.append("")
    lines.append("**Attacker-controlled payload** (the text an adversary plants in "
                 "content the agent ingests):")
    lines.append("")
    lines.append("```")
    lines.append(str(_get(finding, "attack_payload")))
    lines.append("```")
    lines.append("")
    lines.append("**Steps:**")
    lines.append("")
    steps = finding.get("steps")
    if steps:
        for i, step in enumerate(steps, 1):
            lines.append(f"{i}. {step}")
    else:
        lines.append(_PLACEHOLDER)
    lines.append("")
    lines.append(f"**Reproducibility:** {_repro_line(finding, auth)}")
    lines.append("")

    lines.append("## Impact")
    lines.append("")
    lines.append(f"- **Trust boundary crossed:** {_get(finding, 'trust_boundary')}")
    lines.append(f"- **Security-relevant effect:** {_get(finding, 'impact_summary')}")
    lines.append(f"- **Who is harmed:** {_get(finding, 'affected_party', 'another user / the platform')}")
    lines.append("")

    lines.append("## Observed behavior")
    lines.append("")
    lines.append("```")
    lines.append(str(_get(finding, "observed_action")))
    lines.append("```")
    lines.append("")

    lines.append("## Suggested remediation")
    lines.append("")
    lines.append(_get(finding, "remediation"))
    lines.append("")

    lines.append("## Disclosure")
    lines.append("")
    lines.append(f"- Reported under coordinated disclosure"
                 f"{' with safe-harbor protection' if auth.safe_harbor else ''}.")
    lines.append("- Requesting standard embargo until a fix ships; will not publish "
                 "before then.")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("_Generated by AgentProbe v1.2. Before submitting: confirm every "
                 "`[TODO]` is filled, redact any real user data from logs, and verify "
                 "the reproduction was done within the program's testing rules._")

    return "\n".join(lines)
