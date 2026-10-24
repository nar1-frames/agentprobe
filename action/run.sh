#!/usr/bin/env bash
# Runs one AgentProbe command for the composite action. Inputs arrive as AP_*
# environment variables and are never interpolated into this script. The run
# always exits 0 so the SARIF upload still happens; gate.py decides the job.
set -u

out="${AP_OUTPUT_DIR:-agentprobe-results}"
sarif="$out/agentprobe.sarif"
junit="$out/agentprobe.junit.xml"
mkdir -p "$out"
rm -f "$sarif" "$junit"

case "${AP_COMMAND:-scan}" in
  scan)
    agentprobe scan --non-interactive --no-color --config "${AP_CONFIG:-config.yaml}" \
      --sarif "$sarif" --junit "$junit"
    ;;
  demo)
    agentprobe demo --no-color --sarif "$sarif" --junit "$junit"
    ;;
  harness)
    agentprobe harness --mode "${AP_HARNESS_MODE:-guarded}" --no-color \
      --json "$out/agentprobe-harness.json" --sarif "$sarif" --junit "$junit"
    ;;
  *)
    echo "agentprobe action: command must be scan, demo, or harness (got '${AP_COMMAND}')" >&2
    exit 2
    ;;
esac
status=$?

{
  echo "exit-code=$status"
  echo "sarif-file=$sarif"
  echo "junit-file=$junit"
  if [ -s "$sarif" ]; then echo "sarif-written=true"; else echo "sarif-written=false"; fi
} >> "${GITHUB_OUTPUT:-/dev/null}"
exit 0
