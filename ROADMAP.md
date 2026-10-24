# AgentProbe roadmap

This roadmap is deliberately ordered by credibility: safety and reproducibility
come before breadth.

## Now — public foundation

- [x] Installable CLI with local and compatible cloud-provider paths
- [x] Offline fixture harness with requested/blocked/executed tool traces
- [x] Configuration validation, checkpointing, provenance, and private artifacts
- [x] Threat model, security policy, CI, and public-tree hygiene checks
- [x] Research manifest, blinded label packets, and publication gate
- [ ] Complete the v1.4 human labels and judge matrix
- [x] Publish a clean first-run demo and representative sanitized report

## Next — developer-grade security harness

- [x] Versioned attack-pack schema with explicit success oracles (schema 1.0;
  deterministic oracles count in verdicts since 2.1, rule oracle-precedence 1.0;
  judge-evaluated oracles are still decided by the generic judge). External packs load
  through the same path since 2.1 (`--pack`, `packs:`, `docs/PACKS.md`)
- [x] Stable event schema for model, tool, policy, and execution events
  (harness schema 1.4, event schema 1.0, closed ten-event vocabulary)
- [x] SARIF and JUnit output for security and CI workflows (`--sarif`/`--junit`
  on scan and harness; exports never carry response or judge text)
- [x] Baseline and regression comparisons for repeated scans (`agentprobe
  compare`, keyed by attack ID and bound to the library digest)
- [x] Deterministic replay provider for offline debugging (`provider: replay`,
  `scan.record_replay_path`; a miss is an operational error, never a verdict)
- [x] Policy tests for data sinks, filesystem boundaries, network destinations,
  approvals, and tool-chain depth (`ToolPolicy.max_executed_calls`, https host
  allowlist for `http_fetch`, email recipient-domain allowlist; one neutral
  network scenario added to the fixture suite)

## Then — realistic agent coverage

- [ ] RAG and document-ingestion scenarios
- [ ] Memory and multi-turn attack scenarios
- [ ] Browser, code-execution, database, email, and MCP-style tool adapters
- [ ] Framework adapters that normalize into the same policy and trace boundary
- [ ] Cross-tenant and excessive-agency scenarios
- [ ] Independent benchmark comparison with clearly stated limitations

## Release maturity

- [x] Stable Python API and schema compatibility policy
  ([docs/COMPATIBILITY.md](docs/COMPATIBILITY.md): public API list, MAJOR.MINOR
  schema rules, semver, and a deprecation window of one minor release and 90 days)
- [x] Signed release artifacts, SBOM, and build provenance (`release.yml`:
  Sigstore build-provenance attestation, PEP 740 attestations through trusted
  publishing, SPDX SBOM; first exercised by the v2.0.0 tag)
- [x] Pinned CI actions, dependency automation, and static analysis (every
  action pinned to a commit SHA, weekly Dependabot for pip and actions, ruff
  lint gate, CodeQL security-extended scanning)
- [ ] Maintainer and contribution governance
- [ ] Independent security review of the live integration boundary

Progress is tracked against the acceptance criteria in [GOALS.md](GOALS.md),
not by feature count alone.
