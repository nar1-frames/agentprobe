TASK ID: terminal-readability
BRANCH: pg/terminal-readability (from main @ 8aae93a)
GOAL: Make the terminal output of `agentprobe harness` and the non-interactive `agentprobe scan` understandable to a first-time reader (a student, a reviewer, a dev in CI logs) without opening the HTML report: clear status tags, a one-line plain-English meaning per scenario, a legend, a summary with counts, and the exit-code meaning. Plain ASCII by default so CI logs and Windows cp1252 consoles stay clean; ANSI colour only when stdout is a TTY and NO_COLOR is unset.

CONTEXT (already gathered):
- agentprobe/cli.py `_finish_harness` (~line 74) prints "AgentProbe fixture harness — mode: X" (the em dash renders as "?" on Windows cp1252; replace with ASCII) then one line per result: "  <attack_id>: <status>; requested=...; executed=...". Each result dict (HarnessResult.to_dict) has attack_id, category, objective, scenario_kind, attack_succeeded, control_succeeded, requested_tool_calls, executed_tool_calls, blocked_tool_calls [{call, reason}], operational_errors, events.
- `_print_scan_summary` (~line 245) prints three lines (Scan summary / Verdicts / Findings by severity) from report["summary"]; added last task, tested in tests/test_cli.py (keep those tests passing; they assert substrings, check which).
- Exit codes: harness returns 1 with --fail-on-success when any attack succeeded, 3 with --fail-on-error, else 0; scan has --fail-on-error.
- tests/test_cli.py exercises both paths through capsys (not a TTY), so default output must be plain text.
- No colour library exists; do not add one.

IN SCOPE: agentprobe/cli.py presentation only (new small helpers are fine, e.g. a `_style()` that returns ANSI codes only when enabled); tests in tests/test_cli.py; README harness/demo sample output blocks updated to the new shape.
OUT OF SCOPE: harness.py, scanner.py, reporting.py, exports, JSON shape, HTML report, interactive scan path, new dependencies.

REQUIREMENTS:
1. Harness header: "AgentProbe fixture harness (mode: guarded)" plus a second line explaining the mode in <= 80 chars, from a small dict: vulnerable = "no policy gate; shows what an unprotected agent would do", model_only_guarded = "model told to distrust external content; no policy gate", architecture_only_guarded = "policy gate on; model trusts external content", guarded = "policy gate on and model distrusts external content".
2. Per scenario, a block of 2-3 lines:
   [BLOCKED]  harness-indirect-file-boundary  (indirect_injection)
              goal of the attack: <objective>
              requested: none | executed: none
   Status tags, fixed width, left-aligned: [BLOCKED] attack did not reach its objective; [ATTACK OK] attack reached its objective (this is the bad outcome; say so in the legend); [CONTROL OK] / [CONTROL FAIL] for control scenarios; [ERROR] when operational_errors is non-empty (printed in addition, each error on its own indented line). For controls the second line reads "expected behaviour: <objective>".
   When blocked_tool_calls is non-empty, add one line per block: "              blocked <tool>: <reason>".
3. Legend printed once after the scenarios, 4 short lines, e.g.
   Legend: [BLOCKED] the policy or model stopped the attack  [ATTACK OK] the attack worked - fix needed
           [CONTROL OK] normal work still allowed  [ERROR] a tool or model failure, not a verdict
4. Summary line: "Summary: 4 attacks (0 succeeded), 1 control (1 passed), 0 operational errors". Then, only when --fail-on-success or --fail-on-error is set, one line stating the exit code that will be returned and why ("Exit code 1: an attack succeeded and --fail-on-success is set").
5. Scan summary: keep the three existing lines unchanged (tests depend on them) and add a fourth legend line: "Verdict key: SAFE refused, SUSPICIOUS unclear, PARTIAL hedged then complied, VULNERABLE complied". Add after it the existing "report saved" lines unchanged.
6. Colour: helper enables ANSI only if sys.stdout.isatty() and os.environ.get("NO_COLOR") is unset and os.environ.get("TERM") != "dumb". Green for BLOCKED/CONTROL OK, red for ATTACK OK/CONTROL FAIL, yellow for ERROR. Tags keep the same text with or without colour. Add --no-color flag on harness and scan that forces plain.
7. All output ASCII-only by default (no em dash, no unicode box characters, no emoji).
8. Tests (tests/test_cli.py, additions only): test_harness_output_has_tags_legend_and_summary (guarded, capsys; asserts header, mode explanation, a [BLOCKED] tag, the [CONTROL OK] tag, the Legend line, the Summary line, and that no non-ASCII byte appears in captured stdout); test_harness_output_marks_attack_success_and_exit_reason (vulnerable with --fail-on-success; asserts [ATTACK OK] and the "Exit code 1" line, return 1); test_harness_output_lists_blocked_reasons (guarded; asserts a "blocked delete_account:" line with reason "tool is not allowlisted"); test_scan_summary_prints_verdict_key (reuse the existing stubbed-report fixture); test_colour_disabled_when_not_tty (monkeypatch isatty False, assert no "\x1b[" in output) and test_colour_enabled_on_tty_without_no_color (monkeypatch isatty True, NO_COLOR unset, assert "\x1b[" present and --no-color removes it).
9. README: replace the harness sample output block and the demo scan summary block with the real new output (run them to get it). Keep under 25 lines each.
10. Full suite green on Windows: .venv\Scripts\python -m pytest -q.

ACCEPTANCE CRITERIA:
1. Paste real output of `.venv\Scripts\python -m agentprobe.cli harness --mode guarded` and `--mode vulnerable --fail-on-success` (exit code shown), and the demo scan `scan --non-interactive --config demo/replay.yaml` tail.
2. pytest summary line pasted, all green, new test names listed.
3. `git diff main --stat` touches only agentprobe/cli.py, tests/test_cli.py, README.md.
4. No non-ASCII characters in any printed string in cli.py (grep -P "[^\x00-\x7F]" agentprobe/cli.py returns nothing).

CONSTRAINTS: no new deps; do not change JSON/SARIF/JUnit output or any exit code value; existing tests unchanged; conventional commits on the branch; no push, no merge; leave .promptgod/ and the stray agentprobe_v05.py diff alone.
ASSUMPTIONS ALLOWED: exact wording of tags, legend and mode explanations is mine; tighten if clearly better but keep the tag tokens exactly as written since tests and README reference them.
REPORT: STATUS / BRANCH AND COMMITS / FILES CHANGED / REQUIREMENTS / SELF-TEST / KNOWN ISSUES / ASSUMPTIONS / SUGGESTIONS, sent to session "manage-agents-command [31bf39]".
