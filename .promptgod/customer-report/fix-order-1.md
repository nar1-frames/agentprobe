FIX ORDER 1 for TASK customer-report (branch pg/customer-report, commit 822b272)

Decision: FIX. All nine acceptance criteria passed, but debug round 1 found defects that change what a customer reads. Fix each below, add a regression test for each, re-run the full suite, commit on the same branch, and report.

BUG 1 (must fix): a new finding can be listed as a fix.
- Where: agentprobe/customer_report.py lines 238-239 (the regressions/fixes split).
- Repro: baseline has jailbreak:1 as an operational error; candidate has it as VULNERABLE CRITICAL. Report shows "Regressions: None." and "Fixes: jailbreak:1 ... now VULNERABLE, severity CRITICAL".
- Expected: anything that is a finding now and was not a finding before (including errored or absent before) is a regression. Anything that was a finding before and is not now (SAFE now, or errored now with no finding) is a fix only if it is SAFE now; errored now is listed under "could not be compared". Classify by the candidate row's own state first, then by the change class. New attacks (absent in baseline) that are findings now must appear under regressions.
- Test: the exact repro above, asserting the attack appears under regressions and not under fixes.

BUG 2 (must fix): a malformed `run` block crashes with a traceback and exit 1.
- Where: agentprobe/customer_report.py line 462; the --baseline path reaches the same crash through compare.py line 118 (do not modify compare.py; validate before calling it).
- Repro: scan JSON with "run": "x" or "run": [1].
- Expected: validate_customer_input raises ValueError so the CLI prints one line and exits 2. Validate the baseline the same way before compare_scan_reports is called.
- Test: both repro inputs through the CLI, asserting exit 2, one stderr line, no output file.

BUG 3 (must fix): negative or boolean counts are accepted.
- Where: agentprobe/customer_report.py lines 70-72 and the total/error checks below them.
- Repro: summary.findings_by_severity.CRITICAL = -2 renders "150 / 100" with PASS; total_attacks = -5 renders "ran -5 attacks".
- Expected: every count must be a non-negative int and not a bool, else ValueError (exit 2 from the CLI).
- Test: negative severity count and bool count each rejected.

BUG 5 (must fix, same change as bug 3): score and badge can disagree on hand-edited files.
- Expected: in validate_customer_input, recount findings by severity from the result rows and require the counts to equal summary.findings_by_severity; if they differ, ValueError "summary counts do not match result rows". Real scanner output always matches, so this only rejects edited files. Keep score_report reading the summary as specified.
- Test: summary HIGH=3 with no matching rows is rejected.

BUG 4 (decision made, apply it): remove URL defanging.
- Reason: the report is evidence of what the model said. Rewriting quoted output undermines it, and escaped text inside a <p> is not a clickable link in a browser. Remove _URL_SCHEME and its use at lines 57 and 249, the docstring sentence about it, and its test.
- Replace acceptance criterion 3 with: the HTML contains no href=, src=, <link, <img, <iframe, @import, or url( (case-insensitive grep count 0 for each). Keep the "<script" count 0 check. Add one test that renders a response containing "https://example.test/x" and asserts the text is present verbatim and escaped, and that none of the tags above appear.

SMALL (fix in the same commit):
- A scan with total_attacks == 0 must render INCOMPLETE, not PASS 100, with the summary paragraph saying no attacks ran. Add a test.
- Finding headings: put a space or separator between the severity label and the category name so screen readers do not read "HIGHContext manipulation". Verify in the rendered HTML text.
- README: restore the lost line break in the report example so the command is on one line or uses a trailing backslash correctly.

Do not change anything else. Run `.venv/Scripts/python.exe -m pytest -q`, re-run the demo round-trip and the replacement grep checks, commit on pg/customer-report with a message ending in "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>", then append a FIX ROUND 1 section to .promptgod/customer-report/worker-report.md with the commit hash, test count, and the command output for each item above.
