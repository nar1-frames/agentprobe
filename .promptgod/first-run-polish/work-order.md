TASK ID: first-run-polish
BRANCH: pg/first-run-polish (from main @ ea4a3b4)
GOAL: Two small first-run improvements before the user tests by hand. (A) `agentprobe demo`: a one-word command that runs the offline replay scan verbosely, so a new user types one thing and sees progress, summary and the report paths. (B) Make the interactive runner (agentprobe_v12.py) console-safe on Windows: it prints emoji and em dashes that show as "?" on cp1252 consoles. Keep the emoji where the console can render them (the user likes them), fall back to the shared ASCII tags otherwise.

CONTEXT (already gathered):
- README quickstart step 2 is `agentprobe scan --non-interactive --verbose --config demo/replay.yaml`; demo/replay.yaml + demo/scan.replay.json exist; tests/test_demo.py runs the demo through the CLI with a demo_cwd fixture and a network-connect guard.
- cli.build_parser has subcommands scan / harness / compare; scan parser has --non-interactive, --config, --verbose, --no-color, --sarif, --junit, --fail-on-error, checkpoint flags. The non-interactive scan branch in cli.main builds scan_kwargs and calls scanner.run_configured_scan then termstyle.print_scan_summary, saved lines, exports.
- agentprobe_v12.py: VERDICT_ICONS-style dict at ~line 55 (🔴🟠🟡🟢), tags at ~149 (🖥/☁), ⛔/⚠ at ~178/184, "—" in the banner at ~239 and comments. agentprobe/termstyle.py has TAG_* constants, verdict_tag(verdict, method), style(), colour_enabled(), print_scan_summary(). sys.stdout.encoding is "cp1252" on this box's console and "utf-8" under PYTHONUTF8=1 or in most CI.

IN SCOPE: cli.py (demo subcommand), agentprobe_v12.py (console-safe glyphs, banner), termstyle.py (one helper `console_is_unicode()` and/or `glyph(unicode, ascii_fallback)`), tests, README quickstart, demo/README.md.
OUT OF SCOPE: scan logic, report contents, model picking logic, moving v12 into the package.

REQUIREMENTS:
1. `agentprobe demo` = exactly `scan --non-interactive --verbose --config <repo>/demo/replay.yaml` resolved relative to the package or repo root so it works from any cwd (check how test_demo.py locates the config; if the replay config uses relative paths, chdir is not acceptable, so resolve paths inside the config loader or document the cwd requirement and make the command print a clear error "run from the repository root" if the files are missing). Accept --no-color, --sarif, --junit pass-through. Implement by reusing the scan code path (a shared function), not by copying it.
2. Before the scan starts, `demo` prints a 3-line intro: "AgentProbe offline demo: replays a recorded scan of openai/gpt-oss-20b, no keys or network needed." / "Each attack prompt below is judged from the recording; verdict tags are explained at the end." / blank line. ASCII only.
3. termstyle gains `console_is_unicode()` (True when sys.stdout.encoding, lowercased, contains "utf") and `glyph(unicode_text, ascii_text)` returning the first only when the console is unicode. agentprobe_v12.py uses glyph() for every emoji and em dash it prints (banner, verdict icons, local/cloud tags, warning markers); ASCII fallbacks reuse the termstyle tags where a verdict is shown ([VULNERABLE] etc. via verdict_tag) and plain words elsewhere ("local", "cloud", "STOP", "WARNING", "-"). Comments may keep their em dashes.
4. Tests (additions only, exact names): test_demo_command_runs_offline_and_prints_intro (tests/test_demo.py; asserts the intro line, a "category total:" line, "Scan summary:", both saved lines, exit 0, all chars < 128); test_demo_command_reports_missing_files_clearly (monkeypatch the resolved config path to a missing file, assert exit 2 and a message naming the path); test_glyph_falls_back_on_non_unicode_console (tests/test_cli.py or a new tests/test_termstyle.py; monkeypatch sys.stdout.encoding to "cp1252" then "utf-8").
5. README quickstart step 2 becomes `agentprobe demo` with the existing excerpt kept (update it only if the intro lines change the first lines shown). demo/README.md mentions the command.
6. Full suite green on Windows (.venv\Scripts\python -m pytest -q); also run `agentprobe demo` once with PYTHONUTF8 unset and once with PYTHONUTF8=1 and confirm both exit 0 with no "?" replacement glyphs other than the known one in the DAN prompt preview.

ACCEPTANCE CRITERIA:
1. Paste `.venv\Scripts\python -m agentprobe.cli demo` output head (intro + first category) and tail (summary + saved lines), exit 0.
2. pytest summary line, all green, new test names.
3. `git diff main --stat` touches only agentprobe/cli.py, agentprobe/termstyle.py, agentprobe_v12.py, tests/test_demo.py, tests/test_cli.py or tests/test_termstyle.py, README.md, demo/README.md.

CONSTRAINTS: no new deps; termstyle imports nothing from agentprobe; conventional commits on the branch; no push, no merge; leave .promptgod/ and the stray agentprobe_v05.py diff alone. If requirement 1's path resolution turns out to need a change in config loading, stop and report BLOCKED with the exact issue instead of widening scope.
REPORT: usual format, to "manage-agents-command [31bf39]".
