# Debug round 2: customer-report (pg/customer-report @ baf0ba5)

Fixtures: D:\MacSync\projects\research\agentprobe\reports\dbg2\ (built with build_json_report, so they match real scanner output unless named bad_*).

## Acceptance criteria

1. PASS. `.venv/Scripts/python.exe -m pytest -q` -> `413 passed in 6.43s`.
2. PASS. `agentprobe demo` (exit 0) then `agentprobe report --scan reports/scan_openai_gpt-oss-20b_20261022T235631Z_9d6a522f.json --out reports/customer.html --client "Demo Co"` -> `Wrote customer report to reports/customer.html`, exit 0, 10099 bytes. FAIL badge, 40/100 (4 HIGH), title "Demo Co - AI agent security test - FAIL".
3. PASS. grep -i -o -F count on reports/customer.html: `<script` 0, `href=` 0, `src=` 0, `<link` 0, `<img` 0, `<iframe` 0, `@import` 0, `url(` 0. reports/dbg2/url.html (response `visit https://example.test/x and <a href="https://example.test/y">y</a> <img src="https://example.test/z.png">`): blockquote textContent is the response verbatim; document.links=0, images=0, scripts=0; performance resource entries [] and the network log shows only the page GET. (A raw grep on url.html finds href=/src= once each, inside escaped `&lt;a href=` / `&lt;img src=` text. Expected.)
4. PASS. tests/test_customer_report.py:42-92 have names that match their assertions (PASS 95; FAIL 85 on one HIGH; FAIL 75 on CRITICAL plus one error; INCOMPLETE 100 on zero findings plus one error; 40 for 1C+2H+1M; INCOMPLETE on zero attacks). Independent score_report calls: inc.json -> INCOMPLETE/100; zero.json -> INCOMPLETE/100, "no attacks ran"; s40.json (rows 1C, 2H incl. one PARTIAL, 1M, 1 SAFE) -> FAIL/40; crit_err.json -> FAIL/75 with the error reason.
5. PASS. Test at tests/test_customer_report.py:196-206 asserts raw `<script>alert(1)</script>` absent and the `&lt;script&gt;` form present. Independent: xss.json (target_model, reason, response, run_id = `<img src=x onerror=alert(1)>`), plus --client and --prepared-by set to the same string: raw `<img` count 0, escaped form appears 8 times (title, h1, meta x2, summary, excerpt, reason, footer run ID).
6. PASS, all five, via the CLI (report --scan X_cur.json --baseline X_base.json):
   (a) SAFE->VULNERABLE HIGH: Regressions "jailbreak:1 (Jailbreak): now VULNERABLE, severity HIGH", net +1, Fixes None.
   (b) errored->VULNERABLE CRITICAL: under Regressions, Fixes "None.", net +1.
   (c) new tool_misuse:5 VULNERABLE: under Regressions, "New attacks 1", net +1.
   (d) VULNERABLE HIGH -> judge-error: under "Could not be compared" ("now could not be run"), not under Fixes or Regressions. The PARTIAL->SAFE row is under Fixes. Also d2: a former finding now absent and a former finding now complete SUSPICIOUS both land under "Could not be compared".
   (e) different attack_library_sha256: warning sentence shown, the finding article and category table still render. Same result for the README run against a real 2026-09-08 baseline.
7. PASS. All exit 2, exactly one stderr line, no out.html:
   - missing scan: `agentprobe: report input error: [Errno 2] No such file or directory: 'nope.json'`
   - {"hello":1}: `scan is not an AgentProbe report`
   - run "x": `scan has a malformed run block`
   - baseline run [1]: `baseline has a malformed run block`
   - CRITICAL=-2 and HIGH=true: `scan summary findings_by_severity must hold non-negative integer counts`
   - HIGH=3 with no rows: `scan summary counts do not match result rows` (same check for the baseline: `baseline summary counts do not match result rows`)
   Real reports with SUSPICIOUS rows are accepted (exit 0): scan_..._20260908T004806Z_f630b234.json and scan_..._87104412.json. Those SUSPICIOUS rows are judge-error rows. No real file in reports/ has a complete SUSPICIOUS/LOW row, so I built one with build_json_report (susp.json): exit 0.
8. PASS. Served from a scratch copy on http://127.0.0.1:8765, built-in browser.
   - customer.html at 1280x800: badge top/bottom 155/207, score 162/200, lead 156/206, header ends at 226; scrollWidth 1265.
   - customer.html at 375x812: badge 190-236, lead 252-353, scrollWidth 375, no element past the right edge.
   - Stress page layout.html (50-char client, 124-char target, 600-char unbroken response, 400-char URL, long custom category, baseline section): 375 wide gives scrollWidth 375, no overflow; 1280x800 puts the lead bottom at 380.
   - One h1. Heading order H1,H2,H3...,H2(,H2,H3...); no level skipped. Title is set.
   Screenshots were taken at both widths in the browser pane.
9. PASS. `git diff --stat main...pg/customer-report` lists only README.md, agentprobe/cli.py, agentprobe/customer_report.py, tests/test_customer_report.py. The diff of pyproject.toml and requirements.txt is 0 lines. Imports are stdlib plus agentprobe.compare and mitigations (mitigations is already in pyproject py-modules). It runs from cwd /.
10. FAIL. On susp.json (2 complete SUSPICIOUS/LOW rows, 1 SAFE) the first screen shows PASS 96 / 100, and the summary paragraph reads in full "AgentProbe ran 3 attacks against demo-target. None succeeded, so no severity applies." Unclear responses are never mentioned, so nothing on the first screen explains the missing 4 points. The count does appear further down, in the findings intro ("2 responses were unclear ..."). customer_report.py:222-255 (summary_sentence) never counts SUSPICIOUS.

## BUGS

B1 (criterion 10, medium). agentprobe/customer_report.py:222-255. summary_sentence omits unclear (SUSPICIOUS) responses, but they cost 2 points each through summary.findings_by_severity.LOW.
Repro: agentprobe report --scan reports/dbg2/susp.json --out x.html
Expected: the paragraph says something like "2 responses were inconclusive."
Actual: "None succeeded, so no severity applies." next to a score of 96.
Related: highest_severity (line 158) reads summary counts, which include SUSPICIOUS LOW. If the only findings have no rated severity and there are SUSPICIOUS rows, the paragraph can report "highest severity ... LOW" for a row it does not count as a success.

B2 (low). agentprobe/customer_report.py:396-400. The notice is ungrammatical for exactly one error.
Repro: reports/dbg2/inc.json, or the real scan_..._87104412.json.
Actual: "1 attack could not be run because of an operational error. They were not counted as passes; rerun the scan to test them."
The summary sentence handles the singular correctly ("was not counted as a pass").

B3 (low-medium, data loss). agentprobe/cli.py _report: --out equal to --scan (or --baseline) silently overwrites the scan JSON evidence with HTML.
Repro: copy a_cur.json to victim.json; agentprobe report --scan victim.json --out victim.json -> exit 0, and victim.json now starts with <!doctype html>.
Expected: refuse (exit 2) when out resolves to an input path.

B4 (low, hand-edited input only; outside requirement 12's list). Validation (customer_report.py:76-98) does not cross-check summary.operational_errors against error rows, and does not limit finding_severity on finding rows to the four levels. This produces contradictory reports (exit 0):
- bad_ops_mismatch.json: the only row has status "error" and operational_errors is 0. Badge PASS 100, but the category table says INCOMPLETE and the summary says "ran 1 attack ... None succeeded".
- bad_sev_lower.json: a VULNERABLE row with finding_severity "high". Badge PASS 100 while a finding is listed, the category says FAIL, and the paragraph says "highest severity found was unrated".
- bad_error_status_vuln.json: a status "error" VULNERABLE/HIGH row counted in the summary. Badge PASS with score 85 and "None succeeded".
The real scanner cannot produce these (build_json_report derives the counts). An edited file can, and it renders a PASS badge.

## NOTES

- Test changes 822b272..baf0ba5: one assertion removed, the hxxps:// defanging check. The new requirement 8 (URLs shown verbatim) replaces it, and test_urls_in_responses_are_quoted_verbatim_and_never_linked covers the new behaviour. Nothing else was loosened, skipped or xfailed. No TODO/FIXME in the changed files.
- Behaviour beyond the requirements:
  - SAFE -> complete SUSPICIOUS is listed under "Regressions" (classify_change regressed branch), shown as "now SUSPICIOUS, severity LOW". That wording reads like a finding to a customer.
  - Same-verdict severity increases (VULNERABLE MEDIUM -> VULNERABLE CRITICAL) are not listed anywhere, because compare ranks by verdict only.
  - A missing candidate row renders as "now no longer run".
- score_report on a summary-only dict with 1C+2H+1M and no rows returns PASS/40. The badge comes from rows and the score from the summary. render_customer_report prevents this through the recount, so it only matters to direct API callers.
- The excerpt is 300 characters of text plus a " [...]" marker (up to 306 shown).
- Missing-file stderr does not say whether the scan or the baseline was missing, though it does show the path.
- generated_at as a non-date (e.g. 12345) renders verbatim as the scan date without "(UTC)".
- Large input: 500 findings with 2000-char responses render in 0.006 s (0.009 s with a 500-row baseline), 443 KB, 500 articles, CRITICAL first.
- README example run as written (after copying a scan to reports/scan.json, then deleting the copy): exit 0, with --prepared-by and --baseline too.
- The print block is present (customer_report.py:378-386). It drops background fills on .verdict, blockquote, .notice, .badge and .sev, applies break-inside:avoid to .finding, tr and .first-screen, and break-after:avoid to h2/h3. I could not run a real print preview; this was checked statically only.
- Failed --out (a directory) exits 2 with one line and leaves no temp file behind.
