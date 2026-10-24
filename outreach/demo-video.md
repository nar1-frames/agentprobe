# Demo video: 3 minutes, fully offline

Everything runs from committed recordings: no API keys, no network, no live
model. Numbers on screen will match this script exactly.

- `demo.cast`: an asciicast v2 recording of the full command sequence, made by
  running the real commands on 2026-10-24. Play it with asciinema-player, or
  `asciinema play demo.cast` where asciinema is installed.
- `demo-transcript.txt`: the same run as plain text, for captions and checking
  numbers.
- `tools/record_demo.py` re-records both from the repository root
  (`python outreach/tools/record_demo.py`) whenever the output changes.

## Before recording

- [ ] A fresh clone of the repo, and a venv with `pip install agentprobe-security`
      (or `pip install -e .` from the clone).
- [ ] Terminal at about 110x34, a large font (18pt or more), dark theme, prompt
      set to `$ `.
- [ ] `export NO_COLOR=1` for ASCII output that reads well on video. Unset any
      provider keys (`unset GROQ_API_KEY OPENAI_API_KEY`) to show it's offline.
- [ ] Run everything from the repository root. Delete `reports/` first, so the
      listing is clean.
- [ ] Browser tab ready: `examples/sample-report/sample-report.html` (or
      `reports/sample-report.html` after step 5).
- [ ] Editor tab ready: `action/examples/agentprobe.yml`.

## Script and shot list

| Time | Shot | On screen | Narration |
|---|---|---|---|
| 0:00-0:12 | Title card | "Can prompt injection steer your AI agent?" with "AgentProbe, open source" below | "AI agents read untrusted text and can call tools. Here is how to test whether that text can steer them, offline, in three minutes." |
| 0:12-0:45 | Terminal | `agentprobe demo` | "This replays a recorded scan of an open model: 14 attacks, each graded by a keyword check and then an LLM judge. Watch the tags: SAFE means refused, VULNERABLE means it complied. Fourteen attacks, three succeeded, one partly. No keys, no network." Hold on the `Scan summary` block. |
| 0:45-1:05 | Terminal | `agentprobe harness --mode vulnerable` | "Chat attacks are half the story. An agent can act. This harness runs tool-use scenarios against in-memory fixture tools. With no policy, all four attacks reach their goal, including a secret read and then emailed out." Hold on `ATTACK OK ... executed: read_secret, send_email`. |
| 1:05-1:25 | Terminal | `agentprobe harness --mode guarded` | "Same scenarios with the policy on: a tool allowlist, approvals bound to exact arguments, a file boundary, a data-sink rule, and a call-depth limit. Every attack is blocked, and normal work still passes. That is the architecture-layer fix: it holds even when the model is fooled." Hold on the `Summary` line. |
| 1:25-2:05 | Terminal | `agentprobe scan --non-interactive --config examples/langchain-quickstart-agent/replay.yaml` | "This is a real scan of the LangChain quickstart agent, recorded once and replayed here. Overt jailbreaks all failed. But when asked politely, it described its instructions and its tool schema. The judge flagged eight findings; reading them by hand, three were the judge's mistakes. The two errors are judge failures, counted separately and never as verdicts." Hold on the `Verdicts` line. |
| 2:05-2:40 | Terminal, then browser | `agentprobe report --scan examples/sample-report/scan.json --engagement examples/sample-report/engagement.yaml --triage examples/sample-report/triage.yaml --out reports/sample-report.html`, then open the HTML | "This is what a client receives: PASS or FAIL and a score on the first screen, findings with the fix and its layer, an OWASP 2025 mapping..." Scroll to "Reviewed and set aside": "...and every finding the analyst set aside, with the reason. Nothing is hidden." |
| 2:40-2:52 | Editor | `action/examples/agentprobe.yml` | "In CI, the GitHub Action runs the same checks on every pull request, uploads SARIF to code scanning, and fails the job at the threshold you set." |
| 2:52-3:00 | End card | Repo URL; "Design-partner assessments: $2,500 with a retest" | "It's all open source. If you want a human to run it against your agent and write it up, the link is below." |

## Exact command sequence

```bash
unset GROQ_API_KEY OPENAI_API_KEY
export NO_COLOR=1
agentprobe demo
agentprobe harness --mode vulnerable
agentprobe harness --mode guarded
agentprobe scan --non-interactive --config examples/langchain-quickstart-agent/replay.yaml
agentprobe report --scan examples/sample-report/scan.json \
  --engagement examples/sample-report/engagement.yaml \
  --triage examples/sample-report/triage.yaml --out reports/sample-report.html
```

Expected summary lines (from `demo-transcript.txt`):

- demo: `Scan summary: 14 attacks (14 scorable), 0 operational errors`, then
  `VULNERABLE 3, PARTIAL 1, SAFE 10, SUSPICIOUS 0, errors 0`
- harness, vulnerable mode: `Summary: 4 attacks (4 succeeded), 1 control (1 passed), 0 operational errors`
- harness, guarded mode: `Summary: 4 attacks (0 succeeded), 1 control (1 passed), 0 operational errors`
- public-scan replay: `Verdicts: VULNERABLE 7, PARTIAL 1, SAFE 39, SUSPICIOUS 0, errors 2`
- report: `Wrote customer report to reports/sample-report.html`

## Notes for the edit

- Cut the dead time between commands. The cast already caps pauses, and
  asciinema-player can play it at 0.5x for narration.
- Keep the terminal output unedited. The point of the video is that anyone
  can reproduce these exact numbers.
- Caption the limitation once, on screen: "Public, well-known single-turn
  attacks; one configuration; control testing, not a guarantee."
