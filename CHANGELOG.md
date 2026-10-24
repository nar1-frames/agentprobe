# Changelog

All notable changes to AgentProbe are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) as defined in
[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

## [Unreleased]

## [2.0.0] - 2026-10-23

The first release published to PyPI, and the first covered by the
compatibility policy. Install it with `pip install agentprobe-security`.

### Breaking

- The PyPI distribution is named `agentprobe-security`, because the name
  `agentprobe` belongs to an unrelated project. The CLI command and the import
  package are still `agentprobe`.
- Root modules moved into packages, with no compatibility shims:
  `report_html_v11` became `agentprobe.html_report`, `mitigations` became
  `agentprobe.mitigations`, `agentprobe_v12` became `agentprobe.interactive`,
  `agentprobe_v11` became `agentprobe.legacy.v11`, and `disclosure_cli` became
  `disclosure.cli` (run it with `python -m disclosure.cli`). The wheel no
  longer installs top-level `py-modules`.
- A relative `replay_path` now resolves next to the config file that names
  it, not the working directory. Output paths (`output.report_dir`,
  `scan.record_replay_path`, `--checkpoint`) are still relative to the working
  directory.
- The demo config moved from `demo/replay.yaml` to
  `agentprobe/demo/replay.yaml`, and ships in the package.
- The `openai` dependency is bounded `<4` and `groq` `<2`. Building from source
  needs setuptools 77 or newer.
- The historical `agentprobe_v01.py` to `agentprobe_v10.py` scripts and the
  `lessons/` directory were removed from the tree. They remain in Git history.

### Added

- `http` provider: scan a deployed agent's own HTTP endpoint through a JSON
  request template and a response path. It is target-only, uses a fresh session
  per attack, refuses credentials in static headers, and never echoes error
  bodies into evidence.
- `agentprobe report`: a self-contained customer HTML report showing a
  PASS/FAIL/INCOMPLETE result, a 0-100 score, findings with fixes from the
  Mitigation Map, a per-category table, and changes against an optional
  baseline.
- `agentprobe demo`: an offline replay of a recorded scan that needs no keys or
  network and runs from any folder, plus a sanitized sample report in
  `docs/demo/`.
- `replay` provider and `scan.record_replay_path`: deterministic offline
  replay keyed by the SHA-256 of each canonical request. A miss is an
  operational error, never a verdict.
- `agentprobe compare`: baseline and regression comparison keyed by attack
  ID and bound to the attack-library digest, with `--fail-on-regression` and
  `--fail-on-incomparable`, a counted summary and a legend.
- `--sarif` (SARIF 2.1.0) and `--junit` exports for scan and harness reports.
  They never carry response text, judge reasoning, or tool traces.
- Versioned attack packs (schema 1.0) with explicit success oracles. Scan
  reports record `attack_pack_schema_version` and `attack_pack_sha256`.
- Harness event schema 1.0: a closed vocabulary of ten events covering the
  model, tool, policy, execution, and content layers. Harness reports move to
  schema 1.4 and carry `event_schema_version`.
- Harness policy controls: a tool-chain depth limit
  (`ToolPolicy.max_executed_calls`), an https host allowlist for
  `http_fetch`, an email recipient-domain allowlist, and one neutral
  network-destination scenario.
- Readable terminal output: ASCII status tags, a legend, a summary line, and
  a final exit-code line. Colour appears only on an interactive terminal and
  honours `NO_COLOR` and `--no-color`. `scan --verbose` adds per-attack
  progress and a per-category tally.
- `agentprobe.termstyle`: shared terminal helpers with a console-aware glyph
  fallback for cp1252 consoles.
- `CHANGELOG.md` and `docs/COMPATIBILITY.md`.
- CI tests on Ubuntu and Windows (Python 3.10 and 3.12, plus 3.11 on
  Ubuntu), runs ruff, builds the sdist and wheel, runs `twine check`, audits
  the wheel, and installs it into a fresh virtualenv to run the demo. Every
  action is pinned to a commit SHA, and Dependabot proposes pip and
  GitHub Actions updates weekly.
- Release workflow (`release.yml`, triggered by `v*` tags). It checks that
  the tag matches the package version, tests, builds, audits the wheel,
  writes an SPDX SBOM, attests build provenance with Sigstore, and publishes
  to PyPI through trusted publishing from the `pypi` environment.
  `SECURITY.md` explains how to verify a release.

### Changed

- `reporting.TOOL_VERSION` now follows `agentprobe.__version__`, and the
  package version is read from it, so reports and package metadata cannot
  disagree.
- The test suite passes on Windows without weakening the POSIX permission
  checks.
- Prompt God work orders (`.promptgod/`) are workspace metadata and are no
  longer tracked.

### Fixed

- The engineer HTML report (`agentprobe.html_report`, formerly
  `report_html_v11`) nested a triple-quoted f-string inside another one,
  which is a SyntaxError before Python 3.12. On Python 3.10 and 3.11 every
  scan path that writes HTML failed to import. The output is unchanged.
- Customer report: inconclusive responses are explained, the notice uses
  correct plurals, and the report refuses to overwrite its own input files.
- Interactive runner: emoji show on UTF-8 consoles and fall back to ASCII
  tags on cp1252.

### Security

- Cloud study collection requires explicit consent, and explicit study
  context is gated on recorded provenance.

## [1.7.0] - 2026-09-06

Provider model preflight, a versioned GPT-OSS study protocol, pinned
reasoning and text-only target context, and wheel hygiene checks. Not
published to PyPI.

## Earlier versions

Versions 0.1 to 1.6 were developed in the repository without packaged
releases. The README's version history table summarizes them.

[Unreleased]: https://github.com/nar1-frames/agentprobe/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/nar1-frames/agentprobe/releases/tag/v2.0.0
[1.7.0]: https://github.com/nar1-frames/agentprobe/commit/d30500a
