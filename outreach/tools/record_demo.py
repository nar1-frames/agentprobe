"""Re-record outreach/demo.cast and outreach/demo-transcript.txt.

Runs the demo-video command sequence for real and offline (provider keys
removed from the environment, NO_COLOR set), shows each command as if typed
at a "$ " prompt, and timestamps every output line into an asciicast v2 file.
Long pauses are capped so the cast plays back at a watchable pace. asciinema
itself does not record on Windows; this driver works everywhere.

Run from the repository root with agentprobe installed in this interpreter:

    python outreach/tools/record_demo.py
"""

import argparse
import json
import os
import shlex
import subprocess
import sys
import time

COMMANDS = [
    "agentprobe demo",
    "agentprobe harness --mode vulnerable",
    "agentprobe harness --mode guarded",
    "agentprobe scan --non-interactive --config examples/langchain-quickstart-agent/replay.yaml",
    "agentprobe report --scan examples/sample-report/scan.json"
    " --engagement examples/sample-report/engagement.yaml"
    " --triage examples/sample-report/triage.yaml --out reports/sample-report.html",
]
TYPE_DELAY, LINE_GAP_CAP, PAUSE_AFTER = 0.035, 0.12, 1.6


def record(cast_path: str, transcript_path: str) -> int:
    env = {k: v for k, v in os.environ.items() if k not in {"GROQ_API_KEY", "OPENAI_API_KEY"}}
    env.update({"NO_COLOR": "1", "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1"})
    events, transcript, clock, failures = [], [], 0.5, 0

    def emit(text):
        events.append([round(clock, 3), "o", text])

    for command in COMMANDS:
        emit("$ ")
        for ch in command:
            clock += TYPE_DELAY
            emit(ch)
        clock += 0.4
        emit("\r\n")
        transcript.append(f"$ {command}")
        argv = [sys.executable, "-m", "agentprobe.cli"] + shlex.split(command)[1:]
        proc = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, encoding="utf-8")
        last = time.monotonic()
        for line in proc.stdout:
            now = time.monotonic()
            clock += min(now - last, LINE_GAP_CAP)
            last = now
            line = line.rstrip("\n")
            emit(line + "\r\n")
            transcript.append(line)
        code = proc.wait()
        failures += int(code != 0)
        transcript.extend([f"[exit {code}]", ""])
        clock += PAUSE_AFTER

    header = {"version": 2, "width": 110, "height": 34, "timestamp": int(time.time()),
              "title": "AgentProbe: offline demo, harness, public-scan replay, customer report",
              "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"}}
    with open(cast_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(header) + "\n")
        for event in events:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")
    with open(transcript_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(transcript) + "\n")
    print(f"{len(events)} events, {clock:.1f}s of playback, {failures} failed command(s)")
    return 1 if failures else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cast", default="outreach/demo.cast")
    parser.add_argument("--transcript", default="outreach/demo-transcript.txt")
    args = parser.parse_args(argv)
    return record(args.cast, args.transcript)


if __name__ == "__main__":
    sys.exit(main())
