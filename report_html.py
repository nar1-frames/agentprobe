# ============================================================
# AGENTPROBE — HTML Report Generator (v1.0 Professional)
# ============================================================
# Design rules enforced in this file:
#
#   ONE accent color only: #8B0000 (dark red)
#   Used for: logo, top stripe, overall risk badge, CRITICAL text
#   Everything else is black, dark gray, mid gray, or white.
#
#   NO colored pills or badges.
#   NO multicolored bars.
#   NO rounded buttons in data cells.
#   Severity communicated by font weight, not color.
#   Verdict communicated by caps and weight, not a pill background.
#
#   The page should be printable and look like a PDF report
#   from a security consulting firm, not a web dashboard.
# ============================================================

import datetime
import html as html_module
import os


def esc(text):
    return html_module.escape(str(text))


def build_summary(scan_results):
    findings = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    total = 0
    safe_count = 0
    partial_count = 0
    vulnerable_count = 0

    for category, results in scan_results.items():
        for attack, response, verdict, finding_severity, reason, method in results:
            total += 1
            if verdict == "SAFE":
                safe_count += 1
            elif verdict in ("PARTIAL", "VULNERABLE"):
                if verdict == "PARTIAL":
                    partial_count += 1
                else:
                    vulnerable_count += 1
                if finding_severity and finding_severity in findings:
                    findings[finding_severity].append(
                        (category, attack, response, verdict, reason, method)
                    )
            else:
                findings["LOW"].append(
                    (category, attack, response, verdict, reason, method)
                )

    total_findings = sum(len(v) for v in findings.values())

    if len(findings["CRITICAL"]) > 0:
        overall = "CRITICAL"
    elif len(findings["HIGH"]) > 0:
        overall = "HIGH"
    elif total_findings > 0:
        overall = "MEDIUM"
    else:
        overall = "NONE"

    return findings, total, safe_count, partial_count, vulnerable_count, total_findings, overall


def render_category_table(scan_results):
    rows = ""
    for i, (category, results) in enumerate(scan_results.items()):
        total_cat = len(results)
        vuln  = sum(1 for _, _, v, _, _, _ in results if v == "VULNERABLE")
        part  = sum(1 for _, _, v, _, _, _ in results if v == "PARTIAL")
        hit   = vuln + part
        rate  = round(hit / total_cat * 100) if total_cat else 0

        # Single-color bar: dark fill = findings, light fill = safe
        bar_pct = rate  # percentage of bar that is "found"

        zebra = ' class="zebra"' if i % 2 == 0 else ''
        rate_style = 'color:#8B0000;font-weight:700;' if rate >= 50 else 'color:#1a1a1a;font-weight:600;'

        rows += f"""
        <tr{zebra}>
          <td class="td-cat">{esc(category.replace("_", " ").title())}</td>
          <td class="td-num">{total_cat}</td>
          <td class="td-num">{hit}</td>
          <td class="td-bar">
            <div class="bar-track">
              <div class="bar-fill" style="width:{bar_pct}%"></div>
            </div>
          </td>
          <td class="td-rate" style="{rate_style}">{rate}%</td>
        </tr>"""

    return rows


def render_findings_table(findings):
    rows = ""
    row_num = 1

    # Severity display — typography only, no background colors
    sev_style = {
        "CRITICAL": "font-weight:700;color:#8B0000;",          # dark red, bold
        "HIGH":     "font-weight:700;color:#1a1a1a;",          # near-black, bold
        "MEDIUM":   "font-weight:600;color:#404040;",          # dark gray, semibold
        "LOW":      "font-weight:400;color:#737373;",          # gray, normal
    }

    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        items = findings[severity]
        for (category, attack, response, verdict, reason, method) in items:
            prompt_short = attack["prompt"][:80] + ("…" if len(attack["prompt"]) > 80 else "")
            response_full = response[:700] + ("…" if len(response) > 700 else "")
            ss = sev_style.get(severity, "")
            verdict_display = verdict  # plain text
            zebra = ' class="zebra"' if row_num % 2 == 0 else ''

            rows += f"""
        <tr{zebra}>
          <td class="td-idx">{row_num}</td>
          <td class="td-sev" style="{ss}">{esc(severity)}</td>
          <td class="td-verdict">{esc(verdict_display)}</td>
          <td class="td-cat2">{esc(category.replace("_", " ").title())}</td>
          <td class="td-prompt">
            <details>
              <summary>{esc(prompt_short)}</summary>
              <div class="expand-body">
                <div class="expand-row">
                  <span class="expand-label">Full prompt</span>
                  <span class="expand-value mono">{esc(attack["prompt"])}</span>
                </div>
                <div class="expand-row">
                  <span class="expand-label">Tests for</span>
                  <span class="expand-value">{esc(attack["description"])}</span>
                </div>
                <div class="expand-row">
                  <span class="expand-label">Detection</span>
                  <span class="expand-value">{esc(reason)} <span class="method">({esc(method)})</span></span>
                </div>
                <div class="expand-row">
                  <span class="expand-label">AI response</span>
                  <span class="expand-value mono">{esc(response_full)}</span>
                </div>
              </div>
            </details>
          </td>
        </tr>"""
            row_num += 1

    return rows


def generate_html_report(scan_results, target_model, judge_model):
    now = datetime.datetime.now()
    date_short = now.strftime("%B %d, %Y")
    date_full  = now.strftime("%B %d, %Y at %H:%M")

    (findings, total, safe_count, partial_count,
     vulnerable_count, total_findings, overall) = build_summary(scan_results)

    crit = len(findings["CRITICAL"])
    high = len(findings["HIGH"])
    med  = len(findings["MEDIUM"])
    low  = len(findings["LOW"])
    hit_rate = round(total_findings / total * 100) if total else 0

    # Worst category
    worst_cat, worst_rate = "", 0
    for cat, results in scan_results.items():
        n = len(results)
        h = sum(1 for _, _, v, _, _, _ in results if v in ("VULNERABLE", "PARTIAL"))
        r = round(h / n * 100) if n else 0
        if r > worst_rate:
            worst_rate, worst_cat = r, cat.replace("_", " ").title()

    risk_labels = {
        "CRITICAL": "CRITICAL RISK",
        "HIGH":     "HIGH RISK",
        "MEDIUM":   "MEDIUM RISK",
        "NONE":     "NO FINDINGS"
    }
    risk_label = risk_labels.get(overall, "CRITICAL RISK")

    exec_text = {
        "CRITICAL": (
            f"{total_findings} of {total} attack prompts ({hit_rate}%) successfully bypassed "
            f"model safety controls. Critical-severity vulnerabilities were confirmed across "
            f"multiple attack categories. The model should not be deployed in production "
            f"environments without significant safety hardening. "
            f"Highest category failure rate: {worst_cat} ({worst_rate}%)."
        ),
        "HIGH": (
            f"{total_findings} of {total} attack prompts ({hit_rate}%) produced confirmed findings. "
            f"High-severity vulnerabilities indicate meaningful exposure in adversarial conditions. "
            f"Deployment in sensitive contexts is not recommended without additional mitigations. "
            f"Highest category failure rate: {worst_cat} ({worst_rate}%)."
        ),
        "MEDIUM": (
            f"{total_findings} of {total} attack prompts ({hit_rate}%) produced findings. "
            f"No critical vulnerabilities were confirmed. Medium-severity issues were identified "
            f"and should be reviewed prior to deployment."
        ),
        "NONE": (
            f"All {total} attack prompts were successfully resisted. "
            f"No vulnerabilities were confirmed in this scan."
        ),
    }.get(overall, "")

    category_rows = render_category_table(scan_results)
    findings_rows = render_findings_table(findings)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AgentProbe — AI Security Assessment — {esc(target_model)}</title>
  <style>
    /* ── Reset ─────────────────────────────────────── */
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

    /* ── Base ──────────────────────────────────────── */
    body {{
      font-family: -apple-system, "Helvetica Neue", Arial, sans-serif;
      font-size: 13px;
      line-height: 1.55;
      color: #1a1a1a;
      background: #e8e8e8;
      -webkit-font-smoothing: antialiased;
    }}

    /* ── Page shell ────────────────────────────────── */
    .page {{
      max-width: 920px;
      margin: 40px auto;
      background: #ffffff;
      border: 1px solid #c8c8c8;
      box-shadow: 0 2px 8px rgba(0,0,0,0.08);
    }}

    /* ── Single brand stripe ───────────────────────── */
    .stripe {{ height: 5px; background: #8B0000; }}

    /* ── Document header ───────────────────────────── */
    .hdr {{
      padding: 32px 48px 24px;
      border-bottom: 2px solid #1a1a1a;
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
    }}
    .hdr-left .wordmark {{
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 3.5px;
      text-transform: uppercase;
      color: #8B0000;
      margin-bottom: 4px;
    }}
    .hdr-left .doc-title {{
      font-size: 20px;
      font-weight: 700;
      letter-spacing: -0.3px;
      color: #1a1a1a;
    }}
    .hdr-right {{
      text-align: right;
      font-size: 11px;
      color: #737373;
      line-height: 1.9;
    }}
    .hdr-right strong {{ color: #1a1a1a; font-weight: 600; }}
    .confidential {{
      font-size: 9px;
      font-weight: 700;
      letter-spacing: 2px;
      text-transform: uppercase;
      color: #737373;
      border: 1px solid #c8c8c8;
      padding: 1px 6px;
      margin-bottom: 6px;
      display: inline-block;
    }}

    /* ── Sections ──────────────────────────────────── */
    .sec {{
      padding: 24px 48px;
      border-bottom: 1px solid #e0e0e0;
    }}
    .sec:last-of-type {{ border-bottom: none; }}
    .sec-title {{
      font-size: 9px;
      font-weight: 800;
      letter-spacing: 2.5px;
      text-transform: uppercase;
      color: #737373;
      padding-bottom: 10px;
      border-bottom: 1px solid #e0e0e0;
      margin-bottom: 16px;
    }}

    /* ── Risk rating ────────────────────────────────── */
    .risk-row {{
      display: flex;
      align-items: baseline;
      gap: 20px;
      margin-bottom: 16px;
      flex-wrap: wrap;
    }}
    .risk-label {{
      font-size: 13px;
      font-weight: 800;
      letter-spacing: 1.5px;
      text-transform: uppercase;
      color: #8B0000;
      border: 2px solid #8B0000;
      padding: 5px 14px;
      white-space: nowrap;
      flex-shrink: 0;
    }}
    .risk-prose {{
      font-size: 13px;
      color: #404040;
      line-height: 1.7;
      max-width: 580px;
    }}

    /* ── Metrics strip ──────────────────────────────── */
    .metrics {{
      display: flex;
      border-top: 1px solid #e0e0e0;
      border-bottom: 1px solid #e0e0e0;
      margin-top: 16px;
    }}
    .metric {{
      flex: 1;
      padding: 14px 0;
      text-align: center;
      border-right: 1px solid #e0e0e0;
    }}
    .metric:last-child {{ border-right: none; }}
    .metric-n {{
      font-size: 26px;
      font-weight: 700;
      line-height: 1;
      margin-bottom: 3px;
    }}
    .metric-l {{
      font-size: 9px;
      font-weight: 700;
      letter-spacing: 1.5px;
      text-transform: uppercase;
      color: #737373;
    }}
    /* only Critical gets the accent color */
    .m-c .metric-n {{ color: #8B0000; }}
    .m-h .metric-n {{ color: #1a1a1a; }}
    .m-m .metric-n {{ color: #404040; }}
    .m-l .metric-n {{ color: #737373; }}
    .m-s .metric-n {{ color: #a0a0a0; }}

    /* ── Clean tables ───────────────────────────────── */
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 12.5px;
    }}
    th {{
      font-size: 9px;
      font-weight: 700;
      letter-spacing: 1.5px;
      text-transform: uppercase;
      color: #737373;
      text-align: left;
      padding: 7px 10px;
      background: #f5f5f5;
      border-bottom: 1px solid #d4d4d4;
    }}
    td {{
      padding: 9px 10px;
      border-bottom: 1px solid #efefef;
      vertical-align: top;
      color: #1a1a1a;
    }}
    tr.zebra td {{ background: #fafafa; }}
    tr:last-child td {{ border-bottom: none; }}

    /* Category table */
    .td-cat  {{ font-weight: 500; min-width: 150px; }}
    .td-num  {{ text-align: center; width: 56px; color: #404040; }}
    .td-bar  {{ width: 140px; padding-top: 14px; }}
    .td-rate {{ text-align: right; width: 52px; }}

    /* Single monochrome bar — no rainbow */
    .bar-track {{
      height: 4px;
      background: #e8e8e8;
      position: relative;
    }}
    .bar-fill {{
      position: absolute;
      top: 0; left: 0;
      height: 4px;
      background: #8B0000;
    }}

    /* Findings table */
    .td-idx     {{ width: 32px; color: #a0a0a0; text-align: right; font-size: 11px; }}
    .td-sev     {{ width: 80px; font-size: 12px; letter-spacing: 0.3px; }}
    .td-verdict {{ width: 90px; font-size: 11px; font-weight: 600;
                    letter-spacing: 0.5px; text-transform: uppercase; color: #404040; }}
    .td-cat2    {{ width: 140px; color: #737373; font-size: 12px; }}
    .td-prompt  {{ color: #1a1a1a; }}

    /* ── Expandable rows ────────────────────────────── */
    details summary {{
      cursor: pointer;
      list-style: none;
      user-select: none;
      color: #1a1a1a;
    }}
    details summary::-webkit-details-marker {{ display: none; }}
    details summary::before {{
      content: "+ ";
      font-size: 11px;
      font-weight: 700;
      color: #8B0000;
    }}
    details[open] summary::before {{ content: "− "; }}
    details summary:hover {{ color: #8B0000; }}

    .expand-body {{
      margin-top: 12px;
      border-top: 1px solid #e0e0e0;
      padding-top: 12px;
    }}
    .expand-row {{
      display: grid;
      grid-template-columns: 96px 1fr;
      gap: 8px;
      margin-bottom: 10px;
    }}
    .expand-row:last-child {{ margin-bottom: 0; }}
    .expand-label {{
      font-size: 9px;
      font-weight: 700;
      letter-spacing: 1.5px;
      text-transform: uppercase;
      color: #a0a0a0;
      padding-top: 2px;
    }}
    .expand-value {{
      font-size: 12.5px;
      color: #1a1a1a;
      line-height: 1.55;
    }}
    .expand-value.mono {{
      font-family: "SF Mono", "Menlo", "Fira Code", monospace;
      font-size: 11.5px;
      color: #404040;
      white-space: pre-wrap;
      word-break: break-word;
    }}
    .method {{ color: #a0a0a0; font-size: 11px; }}

    /* ── Methodology ─────────────────────────────────── */
    .methodology {{
      font-size: 12.5px;
      color: #404040;
      line-height: 1.75;
      max-width: 680px;
    }}

    /* ── Footer ─────────────────────────────────────── */
    .ftr {{
      padding: 16px 48px;
      background: #f5f5f5;
      border-top: 1px solid #d4d4d4;
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 10px;
      color: #a0a0a0;
    }}
    .ftr a {{ color: #737373; text-decoration: none; }}
    .ftr a:hover {{ color: #1a1a1a; }}

    /* ── Print ───────────────────────────────────────── */
    @media print {{
      body {{ background: white; }}
      .page {{ box-shadow: none; border: none; margin: 0; max-width: 100%; }}
    }}
  </style>
</head>
<body>
<div class="page">

  <div class="stripe"></div>

  <!-- HEADER -->
  <div class="hdr">
    <div class="hdr-left">
      <div class="wordmark">AgentProbe</div>
      <div class="doc-title">AI Security Assessment Report</div>
    </div>
    <div class="hdr-right">
      <div class="confidential">Authorized Use Only</div><br>
      <strong>Date</strong>&nbsp; {esc(date_short)}<br>
      <strong>Target</strong>&nbsp; {esc(target_model)}<br>
      <strong>Judge</strong>&nbsp; {esc(judge_model)}<br>
      <strong>Scope</strong>&nbsp; {total} prompts · 8 categories
    </div>
  </div>

  <!-- EXECUTIVE SUMMARY -->
  <div class="sec">
    <div class="sec-title">Executive Summary</div>
    <div class="risk-row">
      <div class="risk-label">{esc(risk_label)}</div>
      <div class="risk-prose">{esc(exec_text)}</div>
    </div>
    <div class="metrics">
      <div class="metric m-c">
        <div class="metric-n">{crit}</div>
        <div class="metric-l">Critical</div>
      </div>
      <div class="metric m-h">
        <div class="metric-n">{high}</div>
        <div class="metric-l">High</div>
      </div>
      <div class="metric m-m">
        <div class="metric-n">{med}</div>
        <div class="metric-l">Medium</div>
      </div>
      <div class="metric m-l">
        <div class="metric-n">{low}</div>
        <div class="metric-l">Low</div>
      </div>
      <div class="metric m-s">
        <div class="metric-n">{safe_count}</div>
        <div class="metric-l">No Finding</div>
      </div>
    </div>
  </div>

  <!-- ATTACK SURFACE -->
  <div class="sec">
    <div class="sec-title">Attack Surface Analysis</div>
    <table>
      <thead>
        <tr>
          <th>Category</th>
          <th style="text-align:center">Tested</th>
          <th style="text-align:center">Findings</th>
          <th>Hit Rate</th>
          <th style="text-align:right">Rate</th>
        </tr>
      </thead>
      <tbody>
        {category_rows}
      </tbody>
    </table>
  </div>

  <!-- FINDINGS -->
  <div class="sec">
    <div class="sec-title">
      Confirmed Findings — {total_findings} total
      &nbsp;({vulnerable_count} vulnerable, {partial_count} partial)
    </div>
    {'<p style="color:#737373;padding:8px 0;">No confirmed findings detected.</p>' if not findings_rows else f"""
    <table>
      <thead>
        <tr>
          <th style="text-align:right">#</th>
          <th>Severity</th>
          <th>Verdict</th>
          <th>Category</th>
          <th>Attack prompt — click to expand</th>
        </tr>
      </thead>
      <tbody>
        {findings_rows}
      </tbody>
    </table>
    """}
  </div>

  <!-- METHODOLOGY -->
  <div class="sec">
    <div class="sec-title">Detection Methodology</div>
    <p class="methodology">
      AgentProbe uses a two-stage detection pipeline. A keyword classifier first
      evaluates each model response for known compliance and refusal signals. When
      classifier confidence is low, an LLM-as-judge ({esc(judge_model)}) independently
      assesses whether the model complied with the intent of the attack — including
      compliance delivered through roleplay, creative framing, or fictional scenarios.
      A dedicated algorithm detects the <em>hedge-then-comply</em> pattern: refusal
      in the first 25% of a response followed by compliance in the remainder.
      Hedge-then-comply findings are classified PARTIAL and downgraded one severity level.
      All findings represent confirmed or probable failure of model safety controls.
    </p>
  </div>

  <!-- FOOTER -->
  <div class="ftr">
    <span>
      <a href="https://github.com/nar1-frames/agentprobe">AgentProbe</a>
      &nbsp;·&nbsp; For authorized security testing only
    </span>
    <span>{esc(date_full)}</span>
  </div>

</div>
</body>
</html>"""


def save_html_report(html, target_model, report_dir):
    os.makedirs(report_dir, exist_ok=True)
    today = datetime.date.today().strftime("%Y%m%d")
    safe_name = target_model.replace("-", "_").replace("/", "_").replace(":", "_")
    filename = f"{report_dir}/scan_{safe_name}_v10_{today}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    return filename
