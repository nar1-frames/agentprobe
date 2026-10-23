FIX ORDER 2 for TASK customer-report (branch pg/customer-report, head baf0ba5)

Scope: exactly the three items below, each with a regression test. Nothing else changes. Naren approved this round explicitly.

B1 (must fix): the first-screen summary never mentions inconclusive responses, though each costs 2 points.
- Where: agentprobe/customer_report.py lines 222-255 (summary paragraph) and the "highest severity" sentence.
- Repro: a scan with 2 SUSPICIOUS rows and 1 SAFE row renders PASS 96/100 with "None succeeded, so no severity applies." and nothing explains the missing 4 points.
- Expected: the summary paragraph states the count of inconclusive responses whenever it is > 0, in plain words, e.g. "2 responses were inconclusive: the system neither clearly refused nor clearly complied. Each costs 2 points." The "highest severity" sentence must be computed from findings only (VULNERABLE or PARTIAL rows), not from summary counts that include SUSPICIOUS rows, so it never names LOW for a response that was not a success. If there are no findings but there are inconclusive rows, say "No attack succeeded; N were inconclusive."
- Test: the repro above asserts the paragraph contains the inconclusive count and does not claim a severity; a second case with 1 HIGH finding plus 1 SUSPICIOUS row asserts the highest severity is HIGH.

B2 (must fix): singular/plural mismatch in the error notice.
- Where: agentprobe/customer_report.py lines 396-400.
- Expected: "1 attack could not be run ... It was not counted as a pass." and "N attacks could not be run ... They were not counted as passes." Use one small helper for the plural.
- Test: both forms.

B3 (must fix): --out pointing at the scan or baseline file overwrites it with HTML and exits 0.
- Where: the `report` handler in agentprobe/cli.py.
- Expected: before writing, resolve --out, --scan, and --baseline with os.path.realpath; if --out equals either input, print one stderr line ("agentprobe: report error: --out must not be the scan or baseline file") and exit 2 with nothing written. Do the check before any file is opened for writing.
- Test: CLI test with --out equal to --scan asserts exit 2, one stderr line, and the scan file is byte-for-byte unchanged.

Then: `.venv/Scripts/python.exe -m pytest -q` (expect 413 + new tests, 0 failures), re-run the demo round-trip, commit on pg/customer-report with a message ending in "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>", do not merge or push, and append a FIX ROUND 2 section to .promptgod/customer-report/worker-report.md with the commit hash, test count, and command output per item. Leave agentprobe_v05.py and .promptgod/ otherwise untouched.
