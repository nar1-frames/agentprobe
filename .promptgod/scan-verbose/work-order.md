TASK ID: scan-verbose
BRANCH: pg/scan-verbose (from main @ 92336ea)
GOAL: Let the non-interactive scan (including the offline demo) show the new per-attack progress tags, so a first-time user running the README demo sees the scan happen rather than only a summary. Also fix the ordering gap from the last task so the interactive path prints the summary before the "saved" lines.

CONTEXT (already gathered):
- scanner.run_configured_scan (~line 324) calls run_full_scan (~line 384) without `verbose`, so `agentprobe scan --non-interactive` is silent until the summary. run_full_scan(verbose=True) already prints the ASCII tagged progress and category tallies (merged at 92336ea).
- cli.py scan parser: --non-interactive, --config, --checkpoint, --resume, --repair-errors, --fail-on-error, --no-color, --sarif, --junit. _print_scan_summary(report) prints the 4-line summary block.
- agentprobe_v12.main (legacy interactive runner) prints "Report saved to:" lines itself and now returns json_report; cli.main prints the summary after it returns, which is after the saved lines.
- tests/test_cli.py stubs run_configured_scan via _run_with_row; tests/test_demo.py runs the demo end to end through the CLI and asserts on output (read it before changing output order).

IN SCOPE: scanner.run_configured_scan (pass-through verbose kwarg only), cli.py (new --verbose flag on scan, summary ordering), agentprobe_v12.py (call the shared summary printer before its saved lines, and stop cli.main from printing it a second time), tests, README demo block.
OUT OF SCOPE: scan logic, verdicts, reports, exports, other commands.

REQUIREMENTS:
1. run_configured_scan gains `verbose: bool = False` passed straight to run_full_scan. No other signature change.
2. `agentprobe scan --non-interactive --verbose` prints the Target/Judge/Prompts header, the per-category "[CATEGORY] n prompts" lines, the per-attack tag lines and category tallies, then a blank line, then the existing summary block, then the saved lines. Without --verbose, output is unchanged from today.
3. Interactive path: agentprobe_v12.main calls the shared summary printer (import from agentprobe.cli or move _print_scan_summary into termstyle/reporting to avoid a cycle; pick the one that keeps imports clean) before it prints "Report saved to:". cli.main no longer prints it after main() returns. Result: summary appears exactly once, before the saved lines, in both paths.
4. Tests (additions only, exact names): test_scan_non_interactive_verbose_shows_progress (run the offline demo config through the CLI with --verbose, assert "[FIXTURE]"-style category header or the demo's real category names, at least one "[SAFE]" or "[VULNERABLE]" tag, a "category total:" line, and that "Scan summary:" appears after the last "category total:" line and before "HTML report saved to:"); test_scan_non_interactive_quiet_without_verbose (same config, no flag, assert no "category total:" line); test_interactive_scan_summary_precedes_saved_lines (monkeypatch as the existing test_interactive_scan_prints_summary_once does but have the stub print "Report saved to: x" and assert the index ordering and a single "Scan summary:").
5. README quickstart: add `--verbose` to the demo command and show a 6-8 line excerpt of the real demo progress (two attacks from one category plus its tally) above the existing summary excerpt. Keep it under 25 lines total.
6. ASCII-only output; existing tests unchanged; full suite green on Windows (.venv\Scripts\python -m pytest -q).

ACCEPTANCE CRITERIA:
1. Paste the real output of `.venv\Scripts\python -m agentprobe.cli scan --non-interactive --verbose --config demo/replay.yaml` (trim the middle), exit 0.
2. pytest summary line, all green, new test names listed.
3. `git diff main --stat` touches only agentprobe/scanner.py, agentprobe/cli.py, agentprobe_v12.py (and termstyle.py or reporting.py if the printer moves), tests/test_cli.py, tests/test_demo.py (if that is where the demo test lives), README.md.

CONSTRAINTS: no new deps; no cycle (termstyle imports nothing from agentprobe); conventional commits on the branch; no push, no merge; leave .promptgod/ and the stray agentprobe_v05.py diff alone.
REPORT: usual format, to "manage-agents-command [31bf39]".
