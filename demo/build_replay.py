"""Re-cut a local scan JSON report into the committed demo replay recording.

Usage (from the repository root):
    python demo/build_replay.py reports/<scan>.json agentprobe/demo/scan.replay.json

No model is called. Target responses come from the source report, trimmed to
TRIM_CHARS; judge replies are rebuilt from the report's recorded verdict and
reason in the two-line judge format. Requests are produced by the real
scanner (run_full_scan) through RecordingClient, so the digests match exactly
what `agentprobe demo` (agentprobe/demo/replay.yaml) sends.
"""

import json
import re
import sys
from types import SimpleNamespace

from agentprobe.config import load_config
from agentprobe.detection import INTERNAL_TO_LABEL
from agentprobe.replay import RecordingClient
from agentprobe.scanner import filter_attacks, run_full_scan

CONFIG_PATH = "agentprobe/demo/replay.yaml"
TRIM_CHARS = 900
TRIM_MARKER = "\n\n[response trimmed for the demo]"


def _reply(content):
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])


class SourceReportProvider:
    """Answer target and judge requests from a recorded scan report."""

    def __init__(self, report, judge_model):
        self.by_prompt = {row["prompt"]: row for row in report["results"]}
        self.judge_model = judge_model
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **request):
        text = request["messages"][-1]["content"]
        if request["model"] == self.judge_model:
            prompt = re.search(r"<ATTACK_PROMPT>\n(.*?)\n</ATTACK_PROMPT>", text, re.S).group(1)
            row = self.by_prompt[prompt]
            reason = row["reason"].removeprefix("Judge: ").replace("\n", " ").strip()
            return _reply(f"VERDICT: {INTERNAL_TO_LABEL[row['verdict']]}\nREASON: {reason}")
        response = self.by_prompt[text]["response"]
        if len(response) > TRIM_CHARS:
            response = response[:TRIM_CHARS].rstrip() + TRIM_MARKER
        return _reply(response)


def main(source_path, output_path):
    config = load_config(CONFIG_PATH)
    with open(source_path, encoding="utf-8") as handle:
        report = json.load(handle)
    target, judge = config["target"], config["judge"]
    provider = SourceReportProvider(report, judge["model"])
    target_client = RecordingClient(provider, output_path)
    judge_client = RecordingClient(provider, target_client.recording)
    run_full_scan(
        target_client, target["model"], judge_client, judge["model"],
        filter_attacks(config), 0,
        max_tokens=target["max_tokens"], retries=0, retry_delay=0,
        target_temperature=target["temperature"], judge_temperature=judge["temperature"],
        judge_max_tokens=judge["max_tokens"],
        target_reasoning_effort=target.get("reasoning_effort"),
        judge_reasoning_effort=judge.get("reasoning_effort"),
        target_system_prompt=target.get("system_prompt"),
    )
    print(f"wrote {len(target_client.recording.entries)} entries to {output_path}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: python demo/build_replay.py SOURCE_REPORT.json OUTPUT.replay.json")
    main(sys.argv[1], sys.argv[2])
