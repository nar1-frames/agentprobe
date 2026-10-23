TASK ID: scan-summary-line
GOAL: A non-interactive scan prints a short verdict summary to stdout before the "report saved" lines, so the offline demo and CI runs show results in the terminal instead of only file paths.
CONTEXT: agentprobe/cli.py lines 259-290 handle `scan --non-interactive`. It calls scanner.run_configured_scan, then prints only "HTML report saved to" / "JSON report saved to". The run dict carries run["report"] (the JSON report) whose "summary" block (built in agentprobe/reporting.py ~line 165) has total_attacks, scorable_attacks, verdicts {SAFE, SUSPICIOUS, PARTIAL, VULNERABLE}, findings_by_severity, operational_errors. The interactive path already streams verdicts; this is only for the non-interactive path. Note tests/test_cli.py stubs run_configured_scan with a dict that has NO "report" key (see _run_with_row), so the summary must be skipped quietly when report is absent.
IN SCOPE: the summary print in cli.py; a test in tests/test_cli.py; one README line under the demo step showing the expected output shape.
OUT OF SCOPE: interactive path, report contents, harness/compare commands, exit codes, new flags.
REQUIREMENTS:
1. After a successful non-interactive scan, print one block of at most 4 lines, e.g.
   Scan summary: 14 attacks (14 scorable), 0 operational errors
   Verdicts: SAFE 10, SUSPICIOUS 0, PARTIAL 1, VULNERABLE 3
   Findings by severity: HIGH 4
   Severity line lists only non-zero counts; if none, print "Findings by severity: none".
2. Printed before the "report saved" lines, to stdout, using the existing print style (no colour, no emoji; CI logs must stay plain).
3. If run.get("report") is None or lacks "summary", print nothing extra and change no other behaviour.
4. Existing tests in tests/test_cli.py keep passing unchanged. Add one test that stubs run_configured_scan with a report containing a summary and asserts the three lines appear in capsys output; add one asserting no summary lines when report is absent.
5. README: directly under the demo command in the quickstart, add a 3-line indented example of the summary output matching the real demo numbers (run the demo to get them).
6. Full suite green on Windows via .venv\Scripts\python -m pytest -q.
ACCEPTANCE CRITERIA:
1. `agentprobe scan --non-interactive --config demo/replay.yaml` output shows the summary block then the two saved lines; paste output, exit 0.
2. pytest full run summary line pasted, all green, new tests named.
3. `git diff main` touches only agentprobe/cli.py, tests/test_cli.py, README.md.
CONSTRAINTS: no new deps; do not touch scanner.py or reporting.py; leave uncommitted agentprobe_v05.py and .promptgod/ alone; conventional commit (feat:); commit on branch, no push, no merge.
ASSUMPTIONS: wording/format of the lines above is mine; keep it if nothing better is obvious.
BRANCH: pg/scan-summary-line
