TASK ID: customer-report
BRANCH: pg/customer-report (from main @ 4897f40)

GOAL: One command turns a scan JSON report (and optionally the previous one) into a self-contained, print-ready HTML report a customer can forward: executive summary and pass/fail score first, then findings with fixes, then what changed since the last scan.

CONTEXT (already gathered, do not re-discover):
- AgentProbe, Python 3.10+, package in agentprobe/, CLI in agentprobe/cli.py (argparse, subparsers scan/harness/demo/compare; `handler` set_defaults pattern; see compare at ~line 343).
- Scan JSON report shape (built in agentprobe/reporting.py build_json_report ~line 114): keys schema_version, tool, generated_at, target_model, judge_model, run{run_id, tool_version, ...}, summary{total_attacks, scorable_attacks, verdicts{VULNERABLE,PARTIAL,SAFE,SUSPICIOUS}, findings_by_severity{CRITICAL,HIGH,MEDIUM,LOW}, operational_errors}, categories{...}, results[rows]. Row keys: attack_id, category, attack_index, attack_severity, prompt, description, response, verdict, finding_severity, reason, method, status. A finding is a row with verdict VULNERABLE or PARTIAL; finding_severity is set on findings, null otherwise. Rows with status != "complete" or an error method are operational errors, never verdicts.
- Baseline comparison already exists: agentprobe/compare.py compare_scan_reports(baseline, candidate) -> {summary{...CHANGE_CLASSES counts, net_findings_delta}, changes[{attack_id, category, baseline, candidate, change, method_changed}], comparability{...}}. Read CHANGE_CLASSES at the top of compare.py for the exact change names. Reuse it; do not reimplement diffing.
- Per-category mitigation text: mitigations.py MITIGATIONS dict keyed by category with layer, durable, mitigation, owasp. Reuse it for the "how to fix" text.
- The existing HTML report (report_html_v11.py generate_html_report) is the engineer-facing dashboard. It stays as is. The customer report is a new, separate renderer with a different audience: a non-technical buyer who reads the first screen and forwards the file.
- Demo material for tests and manual checks: `agentprobe demo` writes a replay-based scan JSON into reports/ from demo/replay.yaml with no network. reports/ is gitignored; tests must build their inputs in tmp_path.
- tests/test_public_hygiene.py rejects credential-like strings and generated artifacts in the tracked tree. Keep fixtures synthetic.
- Why this matters: the http target provider (commit 4897f40) lets a scan run against a customer's deployed agent. The forwardable report is the thing a customer pays for; without it there is nothing to sell.

IN SCOPE:
- New module agentprobe/customer_report.py: pure functions that take report dict(s) and return the HTML string, plus the score computation.
- New CLI subcommand `agentprobe report` in agentprobe/cli.py.
- Tests in tests/test_customer_report.py (CLI test may live in tests/test_cli.py following its pattern).
- README: one short section under the scan docs showing the command and what the output contains.

OUT OF SCOPE:
- PDF generation libraries (the HTML is print-styled; the user prints to PDF from a browser).
- Changing the scan JSON schema, the engineer HTML report, compare.py, or mitigations.py.
- Scheduling, email delivery, customer config folders, branding assets or logos.
- Any new runtime dependency.

REQUIREMENTS:
1. `agentprobe report --scan PATH [--baseline PATH] --out PATH [--client NAME] [--prepared-by NAME]` writes one self-contained HTML file (inline CSS, no external requests, no script tags) to --out. --scan and --out are required; --baseline is optional. Missing or malformed input exits 2 with a one-line error on stderr and writes nothing.
2. The first screen (visible without scrolling at 1280x800, and readable at 375px wide) contains: client name (or "Unnamed system" if --client is absent), the scan date (generated_at shown as a UTC date), the system label (target_model), the overall result badge PASS / FAIL / INCOMPLETE, the 0-100 score, and a one-paragraph plain-English summary stating how many attacks were run, how many succeeded, and the highest severity found.
3. Result and score rules live in one function `score_report(report) -> {"result", "score", "reasons"}` and are documented in its docstring:
   - FAIL if any finding (verdict VULNERABLE or PARTIAL) has finding_severity CRITICAL or HIGH.
   - INCOMPLETE if summary.operational_errors > 0 and the result would otherwise be PASS. A scan that could not run its attacks must not pass. If it would FAIL anyway it stays FAIL and the error count is still shown.
   - PASS otherwise.
   - score = max(0, 100 - 25*CRITICAL - 15*HIGH - 5*MEDIUM - 2*LOW) from summary.findings_by_severity. The formula is printed in the report footer so a buyer can check it.
4. Findings section: one entry per finding, ordered CRITICAL, HIGH, MEDIUM, LOW, then attack_index. Each entry shows severity, the category in plain words (for example "Role confusion"), the attack's `description` (what it tests), a response excerpt limited to 300 characters, the `reason`, and the mitigation text from MITIGATIONS for that category with its OWASP code. SAFE rows are counted, not listed individually.
5. Category table: every category with attacks run, findings, and a pass/fail mark per category (fail if any finding in that category).
6. "Since last scan" section, only when --baseline is given: counts per change class from compare_scan_reports summary, net_findings_delta, and a list of regressions (attack_id, category, severity now) and fixes. If compare reports the two scans are not comparable (different attack library or schema), show one clear warning sentence instead of the counts and still render the rest of the report.
7. Operational errors: if summary.operational_errors > 0, a short notice states how many attacks could not be run and that they were not counted as passes.
8. Every piece of user-controlled text (client name, prepared-by, prompts, responses, reasons) is HTML-escaped. A response containing `<script>alert(1)</script>` must appear as literal text.
9. Print styling: an @media print block that drops large background fills, avoids page breaks inside a finding entry, and keeps the first screen on page one.
10. Footer: tool version and run_id from the report, the sentence "This report records which configured attacks succeeded against the tested system on the stated date. It is control testing, not a guarantee of safety.", and the score formula.
11. No new dependencies: stdlib plus what pyproject already lists.

ACCEPTANCE CRITERIA:
1. Full suite passes. HOW TO VERIFY: `.venv/Scripts/python.exe -m pytest -q` reports 0 failures and at least 370 plus the new tests.
2. Demo round-trip. HOW TO VERIFY: run `agentprobe demo`, then `agentprobe report --scan reports/<demo json> --out reports/customer.html --client "Demo Co"`; exit 0 and `ls -l reports/customer.html` shows the file.
3. Self-contained. HOW TO VERIFY: `grep -ci "<script" reports/customer.html` prints 0 and `grep -cE "https?://" reports/customer.html` prints 0 (the OWASP code is text, not a link).
4. Score rules. HOW TO VERIFY: unit tests named for each case: PASS; FAIL on one HIGH; FAIL on one CRITICAL with errors present; INCOMPLETE on zero findings with one error; exact score 40 for a synthetic summary of 1 CRITICAL + 2 HIGH + 1 MEDIUM. All pass in pytest output.
5. Escaping. HOW TO VERIFY: a test renders a report whose response is `<script>alert(1)</script>` and asserts the raw tag is absent while `&lt;script&gt;` is present.
6. Baseline section. HOW TO VERIFY: a test builds two synthetic comparable reports where one attack goes SAFE -> VULNERABLE and asserts the HTML lists that attack_id under regressions with net_findings_delta +1; a second test uses incomparable reports and asserts the warning sentence appears while the findings section still renders.
7. Error exit. HOW TO VERIFY: a CLI test runs `report --scan missing.json --out x.html`, asserts exit code 2, one line on stderr, and that x.html does not exist.
8. Layout. HOW TO VERIFY: open reports/customer.html at 1280x800 and at 375 wide; badge, score, and summary paragraph are visible without scrolling at 1280x800; no horizontal scrollbar at 375. Screenshot each.
9. Scope. HOW TO VERIFY: `git diff --stat main...pg/customer-report` lists only agentprobe/customer_report.py, agentprobe/cli.py, tests/test_customer_report.py, README.md, and optionally tests/test_cli.py.

CONSTRAINTS:
- Do not modify reporting.py, compare.py, mitigations.py, report_html_v11.py, or the scan JSON schema.
- Match the package style: module docstring that explains why, type hints, small pure functions, atomic write via reporting._write_text_atomic for the output file.
- ASCII-only terminal output (project convention from pg/terminal-readability); the HTML may use UTF-8.
- Branch from main @ 4897f40; commit on pg/customer-report only; do not merge or push.
- Leave the pre-existing uncommitted change in agentprobe_v05.py and the .promptgod/ folder alone.

ASSUMPTIONS (Naren did not state these):
- HTML with print styling instead of a PDF library, because it needs no dependency and browsers print clean PDFs; a PDF path can be added later behind the same function.
- The score formula above. It is deliberately simple so a buyer can recompute it. It is a communication device, not a risk model.
- SAFE rows are summarized, not listed, so the first page stays about what went wrong.
- Category display names are a small dict in customer_report.py mapping the 8 library categories to title-case phrases.
- "Prepared by" defaults to "AgentProbe" when --prepared-by is absent.

STACK CHECKLIST (PYTHON / GENERAL CODE):
- Runs from a clean start with a documented command
- Tests cover the requirements and pass; empty, bad, and large inputs are handled
- No hardcoded paths, API keys, or secrets; error messages are clear
- Readable names, no dead code, dependencies listed
WEBSITE items that apply to the output file:
- Works at 375px and 1280px wide with no horizontal scroll
- Semantic HTML: exactly one h1, headings in order; page title set
- Readable text contrast

SKILLS TO USE: none required. The worker may load anthropic-skills:avoid-vibecode for the HTML styling pass; it must not add fonts, images, or scripts.
