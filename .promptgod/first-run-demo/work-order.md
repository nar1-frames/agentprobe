TASK ID: first-run-demo
GOAL: A new user can clone the repo, install, and run one documented command that produces a real AgentProbe scan report offline in under a minute, with no API keys or Ollama, and the repo ships one representative sanitized report they can read before running anything.

CONTEXT: AgentProbe (Python 3.10+, package in agentprobe/, CLI in agentprobe/cli.py). ROADMAP.md line 14: "Publish a clean first-run demo and representative sanitized report" is the open item. The replay provider (agentprobe/replay.py, tests/test_replay.py) already lets a scan run with provider: replay and a recorded replay_path for target and judge. Reports go to reports/ and are local-only because they contain raw model output; tests/test_public_hygiene.py enforces what may be committed. Existing JSON reports in reports/ (e.g. scan_openai_gpt-oss-20b_20260908T010104Z_87104412.json) are candidate raw material. Why it matters: the README quickstart currently needs Ollama or cloud keys for a real scan; the harness is credential-free but is not the headline scanner. A zero-setup demo is the first thing a visitor should be able to run.

IN SCOPE:
- A committed demo replay recording and demo config (suggested: demo/replay.yaml and demo/scan.replay.json) covering a small, representative subset of the attack library (10-15 attacks across at least 3 categories, mix of SAFE and VULNERABLE verdicts, at least one hedge-then-comply case if the source data has one).
- Sanitization of the recording: no API keys, no personal paths, no real hostnames, no usernames; model responses reviewed and trimmed to what the verdicts need.
- A committed representative report pair (HTML + JSON) produced from that replay, in a documented public location (suggested: docs/demo/), passing tests/test_public_hygiene.py.
- README quickstart: a new step 2 "Run the offline demo" with the exact command, before the Ollama step. Keep the existing text otherwise.
- A test that runs the demo replay end to end via the CLI non-interactively and asserts it exits 0 and writes a report (tests/test_demo.py).
- Tick the ROADMAP.md item.

OUT OF SCOPE:
- New attacks, new detection logic, changes to replay.py behaviour beyond what the demo needs.
- The "v1.4 human labels and judge matrix" roadmap item.
- The pending whitespace change in agentprobe_v05.py (leave it, do not commit it).
- Any network call in the demo or the test.

REQUIREMENTS:
1. `agentprobe scan --non-interactive --config demo/replay.yaml` runs from a fresh clone with only `pip install -e ".[dev]"`, no env vars, no network, and exits 0.
2. The command finishes in under 60 seconds on a laptop.
3. The demo writes an HTML and a JSON report under reports/ exactly as a real scan does (same code path, no demo-only branch in the scanner).
4. demo/scan.replay.json contains no secrets, no absolute paths, no email addresses, no real hostnames. Grep for "key", "sk-", "gsk_", "C:\\", "/Users/", "@" and justify every hit.
5. The committed docs/demo report shows at least one VULNERABLE finding and at least one SAFE finding, with the Mitigation Map section populated.
6. If the recorded source data is judged by a weaker model than the target, pick a different source recording or set strength_rank explicitly and say so in demo/README.md; the judge-must-be-stronger gate must not be bypassed in code.
7. tests/test_public_hygiene.py and the full suite pass on Windows (`.venv\Scripts\python -m pytest -q`; note `python` on PATH is broken on this machine, use the venv or the Python312 path).
8. README quickstart has the new demo step and the existing steps still read correctly.
9. ROADMAP.md line 14 is ticked.

ACCEPTANCE CRITERIA:
1. Fresh-clone run. HOW TO VERIFY: `git stash -u` is NOT acceptable; instead clone the branch into a temp dir, create a venv, pip install -e ".[dev]", run the demo command with env vars GROQ_API_KEY/OPENAI_API_KEY unset and the network adapter untouched but confirm via the replay provider logs that no HTTP client was constructed. Paste the command output and exit code.
2. Timing. HOW TO VERIFY: `Measure-Command { agentprobe scan --non-interactive --config demo/replay.yaml }` output under 60 s.
3. Report content. HOW TO VERIFY: open docs/demo/*.html, screenshot or quote the summary counts showing both SAFE and VULNERABLE, and the Mitigation Map heading present.
4. Sanitization. HOW TO VERIFY: paste the grep results from requirement 4 with a one-line justification per hit.
5. Tests. HOW TO VERIFY: full pytest output, all green, including the new tests/test_demo.py.
6. Public hygiene. HOW TO VERIFY: tests/test_public_hygiene.py passes with the new files in place; if you had to add an allowlist entry, show the diff and explain why.

CONSTRAINTS:
- Do not edit agentprobe/scanner.py, detection.py, or replay.py unless the demo literally cannot run without it; if you must, explain the one-line reason in the report.
- No new dependencies.
- Follow CONTRIBUTING.md conventions; conventional-commit messages (feat:, docs:, test:).
- Commit on the branch, do not push, do not merge to main.
- Report back tight: files changed, each acceptance criterion with evidence, anything you could not verify, any decision you made that is not in this order.

ASSUMPTIONS (not stated by Naren):
- Demo lives in a top-level demo/ folder and the showcase report in docs/demo/. Change if the repo has a stronger convention.
- Source material is an existing reports/*.json run re-cut into a replay recording, not a fresh live scan. If no existing JSON can be converted into the replay format without a live run, stop and report BLOCKED with the reason rather than running a live scan.
- "Representative" means a subset, not the full 49-prompt library, to keep the artifact small and readable.

STACK CHECKLIST (Python):
- Runs from a clean start with a documented command
- Tests cover the requirements and pass; empty, bad, and large inputs are handled
- No hardcoded paths, API keys, or secrets; error messages are clear
- Readable names, no dead code, dependencies listed

BRANCH: pg/first-run-demo
