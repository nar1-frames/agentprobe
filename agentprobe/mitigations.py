# ============================================================
# AGENTPROBE — Mitigation Map (v1.1)
# ============================================================
# Categorizing which attacks worked answers "what broke."
# This module answers the more useful question: "what do I do
# about it?" — turning a scary success rate into a defense plan.
#
# The core idea encoded here: prompt-injection defenses fall into
# two layers, and only one of them is reliable.
#
#   MODEL layer  — system-prompt hardening, refusal training,
#                  input classifiers. Probabilistic. This is what
#                  a ~50% attack-success rate is measuring. You
#                  cannot prompt your way to safety.
#   ARCHITECTURE — least privilege, treating tool/retrieved data
#                  as untrusted, human-in-the-loop. Reliable,
#                  because it does not depend on the model
#                  choosing to refuse.
#
# Note that AgentProbe's highest-severity categories (tool misuse,
# indirect injection, privilege escalation) are exactly the ones
# the model cannot defend on its own — they MUST be handled at the
# architecture layer.
# ============================================================

# OWASP Top 10 for LLM Applications, 2025 edition: the entries the attack
# categories map to. Each category lists its primary entry first in
# ``owasp_2025``; ``owasp`` repeats that primary code for compact displays.
OWASP_LLM_2025 = {
    "LLM01:2025": "Prompt Injection",
    "LLM02:2025": "Sensitive Information Disclosure",
    "LLM06:2025": "Excessive Agency",
    "LLM07:2025": "System Prompt Leakage",
}

# layer values are grouped so the report can highlight where the
# durable fix actually lives.
MITIGATIONS = {
    "jailbreak": {
        "layer": "Model + Input",
        "durable": False,
        "mitigation": (
            "Enforce instruction precedence in the system prompt, add an input "
            "classifier for known jailbreak patterns, and rely on refusal "
            "fine-tuning. Model-layer only: treat as probabilistic, not a guarantee."
        ),
        "owasp": "LLM01:2025",
        "owasp_2025": ["LLM01:2025"],
    },
    "data_extraction": {
        "layer": "Design",
        "durable": True,
        "mitigation": (
            "Assume the system prompt is public: keep secrets, API keys, and hidden "
            "rules out of it entirely. Redact or rewrite outputs that echo "
            "configuration. The best defense is having nothing worth extracting."
        ),
        "owasp": "LLM07:2025",
        "owasp_2025": ["LLM07:2025", "LLM02:2025"],
    },
    "privilege_escalation": {
        "layer": "Architecture",
        "durable": True,
        "mitigation": (
            "The model must never be the access-control boundary. Enforce "
            "authorization in application code and ignore any role, permission, or "
            "'admin/root' claim made inside the conversation."
        ),
        "owasp": "LLM01:2025",
        "owasp_2025": ["LLM01:2025", "LLM06:2025"],
    },
    "social_engineering": {
        "layer": "Model + Policy",
        "durable": False,
        "mitigation": (
            "Do not grant authority based on identity claims made in chat. Pair "
            "refusal training with a policy that privileged actions require "
            "out-of-band verification, not a convincing message."
        ),
        "owasp": "LLM01:2025",
        "owasp_2025": ["LLM01:2025", "LLM07:2025"],
    },
    "role_confusion": {
        "layer": "Model",
        "durable": False,
        "mitigation": (
            "Persona anchoring and refusal training reduce this but do not eliminate "
            "it. Empirically the highest-success category: measure it every release "
            "and gate deployment on the result rather than assuming it is fixed."
        ),
        "owasp": "LLM01:2025",
        "owasp_2025": ["LLM01:2025"],
    },
    "indirect_injection": {
        "layer": "Architecture",
        "durable": True,
        "mitigation": (
            "Treat ALL retrieved or tool-returned content as untrusted data, never "
            "instructions. Delimit and 'spotlight' external content, neutralize "
            "embedded directives, and track provenance. The most dangerous real-world "
            "vector for tool-using agents."
        ),
        "owasp": "LLM01:2025",
        "owasp_2025": ["LLM01:2025"],
    },
    "context_manipulation": {
        "layer": "App",
        "durable": True,
        "mitigation": (
            "Keep conversation state and guardrails server-side. Ignore in-band "
            "'reset / forget everything / your instructions expired' claims; the "
            "model should not manage its own guardrail lifecycle."
        ),
        "owasp": "LLM01:2025",
        "owasp_2025": ["LLM01:2025"],
    },
    "tool_misuse": {
        "layer": "Architecture",
        "durable": True,
        "mitigation": (
            "Least privilege on every tool, allowlist permitted actions, sandbox "
            "execution, and require human-in-the-loop for consequential calls. Model "
            "refusals are unreliable, so put the guardrail at the tool layer, not the prompt."
        ),
        "owasp": "LLM06:2025",
        "owasp_2025": ["LLM06:2025", "LLM01:2025"],
    },
}

_SEV_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _highest_finding_severity(results):
    """Highest finding_severity present in a category's results, else None."""
    best = None
    for _attack, _resp, _verdict, finding_severity, _reason, _method in results:
        if finding_severity and finding_severity in _SEV_ORDER:
            if best is None or _SEV_ORDER.index(finding_severity) > _SEV_ORDER.index(best):
                best = finding_severity
    return best


def _esc(text):
    import html as _h
    return _h.escape(str(text))


def render_mitigation_section(scan_results):
    """
    Render an HTML section (reusing the report's existing CSS classes) that maps
    each attack category to its recommended defense, sorted worst-first and
    highlighting categories that produced CRITICAL findings.
    """
    # Sort categories: those with findings first, by severity, then name.
    def sort_key(item):
        cat, results = item
        sev = _highest_finding_severity(results)
        rank = _SEV_ORDER.index(sev) if sev else -1
        return (-rank, cat)

    rows = ""
    for cat, results in sorted(scan_results.items(), key=sort_key):
        info = MITIGATIONS.get(cat, {"layer": "—", "durable": False,
                                     "mitigation": "No mapping available."})
        sev = _highest_finding_severity(results)
        sev_display = sev if sev else "—"

        # Typography-based emphasis, consistent with the report's design rules.
        if sev == "CRITICAL":
            sev_style = "font-weight:700;color:#8B0000;"
        elif sev == "HIGH":
            sev_style = "font-weight:700;color:#1a1a1a;"
        elif sev in ("MEDIUM", "LOW"):
            sev_style = "font-weight:600;color:#404040;"
        else:
            sev_style = "font-weight:400;color:#a0a0a0;"

        layer = info["layer"]
        # Architecture/Design/App = durable fix; mark it so the reader sees where
        # the real defense lives.
        layer_style = ("font-weight:700;color:#1a1a1a;" if info["durable"]
                       else "font-weight:400;color:#737373;")
        layer_tag = layer + (" ◆" if info["durable"] else "")

        rows += (
            '\n        <tr>'
            '<td class="td-cat">' + _esc(cat.replace("_", " ").title()) + '</td>'
            '<td class="td-sev" style="' + sev_style + '">' + _esc(sev_display) + '</td>'
            '<td style="' + layer_style + 'width:150px;font-size:12px;">' + _esc(layer_tag) + '</td>'
            '<td style="color:#404040;font-size:12.5px;line-height:1.55;">' + _esc(info["mitigation"]) + '</td>'
            '</tr>'
        )

    section = (
        '\n  <!-- MITIGATION MAP -->\n'
        '  <div class="sec">\n'
        '    <div class="sec-title">Mitigation Map &mdash; Recommended Defenses</div>\n'
        '    <p class="methodology" style="margin-bottom:14px;">\n'
        '      Prompt-injection defenses fall into two layers. <strong>Model-layer</strong> '
        'defenses (system-prompt hardening, refusal training, input classifiers) are '
        'probabilistic &mdash; they are what this scan\'s success rate measures, and cannot be '
        'relied upon alone. <strong>Architecture-layer</strong> defenses (least privilege, '
        'treating tool and retrieved content as untrusted, human-in-the-loop) are durable '
        'because they do not depend on the model choosing to refuse. Rows marked '
        '<strong>&#9670;</strong> have their real fix at the architecture/design layer; the '
        'highest-severity categories are precisely the ones the model cannot defend on its own.\n'
        '    </p>\n'
        '    <table>\n'
        '      <thead><tr>'
        '<th>Category</th>'
        '<th>Highest Finding</th>'
        '<th>Defense Layer</th>'
        '<th>Recommended Mitigation</th>'
        '</tr></thead>\n'
        '      <tbody>' + rows + '\n      </tbody>\n'
        '    </table>\n'
        '  </div>\n'
    )
    return section
