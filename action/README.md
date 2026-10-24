# AgentProbe GitHub Action

Run an AgentProbe prompt-injection scan or the offline agent security harness
in CI, upload the results to GitHub code scanning, and fail the job when a
verdict crosses your threshold.

The Action installs `agentprobe-security` from PyPI. It runs one command and
always writes SARIF and JUnit files. `gate.py` then reads the SARIF to decide
whether the job passes. The SARIF is data-minimized: it carries attack IDs,
categories, severities, verdicts, and methods, never model responses or
judge reasoning.

## Quick start: offline harness, no secrets

```yaml
permissions:
  contents: read
  security-events: write   # only needed for upload-sarif

jobs:
  agentprobe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: nar1-frames/agentprobe/action@v2.0.0   # pin a full commit SHA in practice
        with:
          command: harness
```

## Scan a model or a deployed agent

Commit an AgentProbe config (see `config.yaml` in this repository; the `http`
provider targets your own agent endpoint). Pass provider keys through `env`
from repository secrets, never in the config.

```yaml
      - uses: nar1-frames/agentprobe/action@v2.0.0
        with:
          command: scan
          config: agentprobe.yaml
          fail-on: partial
        env:
          GROQ_API_KEY: ${{ secrets.GROQ_API_KEY }}
```

`command: demo` replays the bundled offline recording. It needs no keys and
is a quick way to see the Action's output before wiring a real target. The
demo contains recorded VULNERABLE findings, so it fails at the default
`fail-on: vulnerable`.

A complete workflow with both jobs is in [examples/agentprobe.yml](examples/agentprobe.yml).

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `command` | `scan` | `scan` (target and judge from `config`), `demo` (offline replay), or `harness` (offline agent harness) |
| `config` | `config.yaml` | Scan configuration; used by `scan` only |
| `harness-mode` | `guarded` | `guarded`, `vulnerable`, `model_only_guarded`, or `architecture_only_guarded` |
| `fail-on` | `vulnerable` | Lowest scan verdict that fails the job: `vulnerable`, `partial`, `suspicious`, or `never`. For `harness`, anything but `never` fails when an attack reaches its objective or a benign control is blocked |
| `fail-on-error` | `true` | Also fail when a target, judge, or tool call errored. Errors are never counted as verdicts |
| `upload-sarif` | `true` | Upload SARIF to code scanning. Needs `security-events: write`; set `false` for fork pull requests or private repositories without code scanning |
| `sarif-category` | `agentprobe` | Code scanning category; use a different one per job |
| `output-dir` | `agentprobe-results` | Where the SARIF, JUnit, and harness JSON files go |
| `package` | `agentprobe-security==2.0.0` | pip requirement to install; matches the release the Action ships with |
| `python-version` | `3.12` | Python used to run AgentProbe |

## Outputs

`result` (`pass` or `fail`), `sarif-file`, `junit-file`, and counts:
`vulnerable`, `partial`, `suspicious`, `safe` (scan and demo),
`attacks-succeeded` and `controls-failed` (harness), and `operational-errors`.
The job summary shows the same counts as a table.

## Badges

A badge for the workflow that runs the Action:

```markdown
[![AgentProbe](https://github.com/OWNER/REPO/actions/workflows/agentprobe.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/agentprobe.yml)
```

A static "tested with" badge:

```markdown
[![Tested with AgentProbe](https://img.shields.io/badge/tested%20with-AgentProbe-blue)](https://github.com/nar1-frames/agentprobe)
```

## Data handling and limits

- The scan's raw JSON and HTML reports contain model responses. They stay on
  the runner in `reports/` unless you upload them yourself. Do not attach them
  to public workflow runs.
- Scan only models and endpoints you own or are authorized to test.
- A passing run is evidence about the attacks in the library at that commit,
  not a guarantee that the agent is safe.
- The gate reads SARIF, so it works with any `agentprobe-security` 2.x.

## For maintainers: Marketplace listing

GitHub Marketplace lists only actions whose `action.yml` sits at the root of
a repository. This one lives in `action/`, which works for `uses:` but cannot
be listed. To publish it, mirror `action/` into the root of a dedicated
repository (for example `nar1-frames/agentprobe-action`), tag a release
there, and publish that release to the Marketplace. Bump the `package`
default with every AgentProbe release; `tests/test_action_gate.py` fails
when it drifts.
