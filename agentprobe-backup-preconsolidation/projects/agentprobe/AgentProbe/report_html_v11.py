# ============================================================
# AGENTPROBE — HTML Report Generator (v1.1)
# ============================================================
# v1.1 adds the Mitigation Map: every attack category is mapped
# to a recommended defense, so the report ends with an action
# plan instead of just a severity count.
#
# This module reuses the v1.0 report wholesale and injects one new
# section (built with the same CSS classes) just before the
# Detection Methodology section — so styling stays identical and
# there is no duplicated markup to maintain.
# ============================================================

from mitigations import render_mitigation_section

# Import the base v1.0 generator. On Python < 3.12 the base file's
# nested f-strings won't compile; fall back to a compatibility copy
# if one is present (used only for local testing on older Pythons).
try:
    from report_html import generate_html_report as _base_generate, save_html_report
except SyntaxError:                       # pragma: no cover
    from report_html_py310 import generate_html_report as _base_generate, save_html_report


def generate_html_report(scan_results, target_model, judge_model):
    """v1.1 report = v1.0 report + Mitigation Map injected before Methodology."""
    html = _base_generate(scan_results, target_model, judge_model)
    section = render_mitigation_section(scan_results)

    anchor = "  <!-- METHODOLOGY -->"
    if anchor in html:
        return html.replace(anchor, section + anchor, 1)
    # Fallback: if the anchor ever changes, append before the footer.
    return html.replace("  <!-- FOOTER -->", section + "  <!-- FOOTER -->", 1)
