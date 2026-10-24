# Changelog

All notable changes to AgentProbe are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) as defined in
[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

## [Unreleased]

### Added

- External attack packs. A pack is a folder holding `manifest.yaml`
  (schema_version 1.0, id, version, license, categories) and `attacks/*.yaml`
  in the existing attack schema with oracles.
  - Load packs with `agentprobe scan --pack` or a top-level `packs:` config
    list (relative paths next to the config). Check them with `agentprobe
    packs list` and `agentprobe packs validate`.
  - The built-in library is now the pack `agentprobe-core` 1.0.0 on the same
    code path. A built-in-only selection and its digests are unchanged.
  - Scan reports add `run.attack_packs` (identity and digest of every pack,
    never a path). Rows from external packs use the ID
    `pack-id:attack-id`. The customer report names the packs.
  - `docs/PACKS.md` is the authoring guide, and
    `examples/packs/support-desk-sample/` is an example pack.
- `outreach/tools/record_demo.py` re-records the demo cast and transcript.

### Changed

- `scan.categories` accepts any lowercase snake_case category name. A
  category that no loaded pack provides is rejected when attacks are
  selected, still before any request is sent.

## [2.0.0] - Unreleased (set the date when tagging v2.0.0)

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
- HTML report filenames drop the historical `_v11_` infix. They are now
  `scan_<model>_<UTC stamp>_<run id>.html`, the same shape as the JSON
  report. Compatibility note: scripts that globbed `*_v11_*.html` should
  match `scan_*.html` instead. The run ID suffix still pairs each HTML file
  with its JSON report.

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
- Assessment package:
  - `docs/ASSESSMENT.md`, the end-to-end runbook for a fixed-fee assessment;
  - `offer/one-pager.md`, the design-partner offer;
  - `examples/sample-report/`, a sample customer report (HTML and PDF)
    rendered from the public scan with an engagement header and analyst
    triage, which a test keeps in sync with the code;
  - `site/index.html`, a static landing page, published by a SHA-pinned
    `pages.yml` workflow.
- Customer report for paid engagements:
  - an engagement header from `--engagement` YAML (client, engagement ID,
    assessment window, system, scope, prepared by, contact, authorization);
  - analyst triage from `--triage` YAML: judge findings set aside as false
    positives with a required reason. The file is bound to the scan's
    `run_id`, set-aside rows cost no points, and they are listed in their
    own section;
  - an OWASP Top 10 for LLM Applications (2025) column per category;
  - a "Not tested and inconclusive" section;
  - a methodology appendix with the run's provenance.
- GitHub Action (`action/`): a composite action that installs
  agentprobe-security and runs `scan`, `demo`, or `harness`. It uploads
  SARIF to code scanning and fails the job at a configurable verdict
  threshold (`fail-on`: vulnerable, partial, suspicious, never), optionally
  also on operational errors. It writes counts as step outputs and a job
  summary. The gate (`action/gate.py`) reads only the data-minimized SARIF,
  so it works with any 2.x release. A self-test workflow exercises the
  action offline on Ubuntu and Windows.
- `examples/langchain-quickstart-agent/`: the LangChain v1 quickstart agent
  behind a local HTTP endpoint, a scan config, and a reviewed recording of one
  live run with a replay config that reproduces it offline. It backs
  `writeups/public-scan-01.md`, and `tests/test_public_scan.py` checks the
  replay on every CI run. The hygiene allowlist names this one recording.
- `docs/BENCHMARK.md`: the methodology, fixed before any data, for a future
  framework comparison.
- CodeQL code scanning (`codeql.yml`) on pushes to main, on pull requests,
  and weekly, with the `security-extended` query suite. Its actions are
  pinned to commit SHAs.

### Changed

- OWASP references use the 2025 edition of the OWASP Top 10 for LLM
  Applications. The previous codes came from the 2023 list. Data extraction
  is now LLM07:2025 System Prompt Leakage, plus LLM02:2025 Sensitive
  Information Disclosure. Tool misuse is now LLM06:2025 Excessive Agency,
  plus LLM01:2025 Prompt Injection. Indirect injection is LLM01:2025. Read
  against the 2025 list, the old codes named the wrong risks.
- `reporting.TOOL_VERSION` now follows `agentprobe.__version__`, and the
  package version is read from it, so reports and package metadata cannot
  disagree.
- The test suite passes on Windows without weakening the POSIX permission
  checks.
- Prompt God work orders (`.promptgod/`) are workspace metadata and are no
  longer tracked.

### Fixed

- Scan reports no longer count failed calls as verdicts. In 1.x,
  `summary.verdicts` and each category's `verdicts` counted error rows under
  their placeholder verdict (SUSPICIOUS), so the terminal line could show
  "SUSPICIOUS 2" when the two rows were judge errors. Verdict counts now
  cover completed rows only, so they sum to `scorable_attacks`, and failed
  calls are counted only in `operational_errors`. The scan schema stays 1.0:
  no field was added or removed, and the values now match the documented
  rule. The terminal Verdicts line ends with `errors N`.
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
