# Compatibility policy

This policy covers AgentProbe 2.0.0 and later, published on PyPI as
`agentprobe-security`. The 1.x line was never published and is not covered.

AgentProbe follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The version is `agentprobe.__version__`. Every scan and harness report records
it as `tool_version`.

## What is stable

Four surfaces are stable within a major version:

1. **The public Python API** listed below.
2. **The CLI:** command names, flags, the meaning of each flag, and exit
   codes.
3. **Artifact schemas:** the JSON documents AgentProbe writes and reads, each
   identified by its own schema version.
4. **Configuration keys:** the YAML keys `agentprobe.config.validate_config`
   accepts, and what they mean.

### Public Python API

Only the names below are public. Everything else is internal and may change
in any release: names with a leading underscore, unlisted modules
(`agentprobe.interactive`, `agentprobe.termstyle`, `agentprobe.html_report`,
`agentprobe.mitigations`, `agentprobe.legacy`), and the top-level `attacks`,
`disclosure` and `research` packages, which ship for the CLI and the study
tooling.

| Module | Public names |
|---|---|
| `agentprobe` | `__version__` |
| `agentprobe.cli` | `main(argv) -> int` (returns the exit code) |
| `agentprobe.config` | `load_config`, `validate_config`, `client_config`, `SUPPORTED_PROVIDERS`, `VALID_CATEGORIES`, `VALID_SEVERITIES` |
| `agentprobe.scanner` | `run_configured_scan`, `run_full_scan`, `filter_attacks` |
| `agentprobe.providers` | `build_client`, `preflight_model` |
| `agentprobe.detection` | `keyword_check`, `llm_judge`, `assess_vulnerability`, `calculate_finding_severity`, `parse_judge_output`, `VULNERABLE`, `PARTIAL`, `SAFE`, `SUSPICIOUS`, `JUDGE_PROMPT_VERSION` |
| `agentprobe.reporting` | `build_run_metadata`, `build_json_report`, `build_harness_report`, `save_json_report`, `save_harness_report`, `SCHEMA_VERSION`, `HARNESS_SCHEMA_VERSION`, `TOOL_VERSION` |
| `agentprobe.events` | `make_event`, `validate_event`, `validate_events`, `EVENT_SCHEMA_VERSION` |
| `agentprobe.harness` | `ToolCall`, `AgentModel`, `ToolExecutor`, `ToolPolicy`, `Scenario`, `HarnessResult`, `AgentRuntime`, `OpenAICompatibleAgent`, `policy_for`, `run_scenario`, `run_fixture_suite`, `run_live_fixture_suite` |
| `agentprobe.exports` | `scan_report_to_sarif`, `harness_report_to_sarif`, `scan_report_to_junit`, `harness_report_to_junit` |
| `agentprobe.compare` | `compare_scan_reports`, `format_comparison_text`, `validate_scan_report`, `COMPARISON_SCHEMA_VERSION` |
| `agentprobe.customer_report` | `render_customer_report`, `score_report` |
| `agentprobe.attackpack` | `build_attack_pack`, `validate_attack_pack`, `attack_pack_digest`, `attack_pack_id`, `ATTACK_PACK_SCHEMA_VERSION` |
| `agentprobe.replay` | `ReplayClient`, `ReplayRecording`, `RecordingClient`, `ReplayMiss`, `load_recording`, `REPLAY_SCHEMA_VERSION` |
| `agentprobe.http_target` | `build_http_target`, `HttpTargetError` |
| `agentprobe.checkpoints` | `ScanCheckpoint`, `CheckpointError` |

### CLI exit codes

| Code | Meaning |
|---|---|
| 0 | Completed, and no `--fail-on-*` condition was met |
| 1 | An attack succeeded (`--fail-on-success`) or regressed or newly errored (`--fail-on-regression`) |
| 2 | Usage, configuration, or input error; nothing was scanned or written |
| 3 | An operational error was recorded and `--fail-on-error` is set |
| 4 | The reports are not comparable and `--fail-on-incomparable` is set |

Human-readable terminal output (tags, wording, layout, colour) and the HTML
report layouts are **not** stable interfaces. Machines should read the JSON
reports, `--json`, SARIF, or JUnit.

## Artifact schemas

| Artifact | Field | Current |
|---|---|---|
| Scan report (JSON) | `schema_version` | 1.0 |
| Harness report (JSON) | `schema_version` | 1.4 |
| Harness event vocabulary | `event_schema_version` (in harness reports) | 1.0 |
| Attack pack | `schema_version` | 1.0 |
| Comparison (`compare --json`) | `schema_version` | 1.0 |
| Scan checkpoint | `schema_version` | 1.0 |
| Replay recording | `schema_version` | 1.0 |
| SARIF export | `version` | 2.1.0 (the SARIF standard) |

Schema versions are `MAJOR.MINOR`, and they move independently of the package
version.

- **Minor bump (1.4 to 1.5):** additive and backwards compatible. A new
  optional field, or a new event type in the harness event vocabulary.
  Consumers must ignore fields they do not know. A consumer built for event
  schema 1.0 may ignore event types it does not know when it reads 1.x.
- **Major bump (1.x to 2.0):** a field is removed, renamed, or changes type
  or meaning; a required field is added; an event type or one of its required
  fields is removed or renamed; or verdict, severity, or status values change
  meaning. A major schema bump ships only in a major package release and is
  listed under "Breaking" in the changelog.
- **Scan report counts.** `summary.verdicts` and each category's `verdicts`
  count completed rows only, so they sum to `scorable_attacks`. Failed
  target or judge calls are counted only in `operational_errors`. Their rows
  keep a placeholder `verdict` with `status: "error"`; read `status` before
  `verdict`. Reports written by 1.x counted error rows under SUSPICIOUS.
- **Working files are read strictly.** Checkpoints and replay recordings are
  local working files, not interchange formats. AgentProbe reads only the
  exact schema version it writes, and refuses anything else rather than
  guessing.
- **The harness event vocabulary is closed per version.** A producer never
  emits an event type that is not registered for the `event_schema_version`
  it declares, and harness serialization refuses unregistered or malformed
  events.
- **The attack library is versioned by digest, not by schema.** Adding or
  editing attack prompts changes `attack_library_sha256`, and `agentprobe
  compare` treats reports from different libraries as incomparable. Library
  changes ship in minor releases and are called out in the changelog.
- **Judge prompt changes** bump `JUDGE_PROMPT_VERSION` and its recorded digest.
  They can change verdicts, so they ship in minor releases under "Changed".

## Semantic versioning

| Release | May contain |
|---|---|
| Major (3.0.0) | Removal or incompatible change of a public API name, CLI command, flag, exit code, or config key; a major artifact-schema bump; removal of anything deprecated in the previous major |
| Minor (2.1.0) | New features, commands, flags, providers, and scenarios; additive schema minor bumps; attack-library and judge-prompt changes; new deprecations; dropping a Python version after its upstream end of life (announced one minor release ahead) |
| Patch (2.0.1) | Bug fixes, documentation, and dependency-bound updates that do not change documented behaviour |

Supported Python versions are those tested in CI: 3.10 through 3.12.

## Deprecation window

- A stable API name, CLI flag, or config key is deprecated for at least one
  minor release **and** at least 90 days before it can be removed. Removal
  happens only in the next major release.
- Deprecated Python APIs emit `DeprecationWarning`. Deprecated CLI flags and
  config keys print a one-line warning to stderr and keep working until
  removal.
- Every deprecation is listed under "Deprecated" in `CHANGELOG.md`, together
  with its replacement and the earliest version that may remove it.
- Security fixes may override the window. If keeping a behaviour would leave
  users exposed, it can change in a minor or patch release, with a "Security"
  changelog entry explaining why.
