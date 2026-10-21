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
- [ ] Publish a clean first-run demo and representative sanitized report

## Next — developer-grade security harness

- [x] Versioned attack-pack schema with explicit success oracles (schema 1.0;
  oracle evaluation is not yet wired into scan verdicts)
- [x] Stable event schema for model, tool, policy, and execution events
  (harness schema 1.4, event schema 1.0, closed ten-event vocabulary)
- [x] SARIF and JUnit output for security and CI workflows (`--sarif`/`--junit`
  on scan and harness; exports never carry response or judge text)
- [x] Baseline and regression comparisons for repeated scans (`agentprobe
  compare`, keyed by attack ID and bound to the library digest)
- [x] Deterministic replay provider for offline debugging (`provider: replay`,
  `scan.record_replay_path`; a miss is an operational error, never a verdict)
- [ ] Policy tests for data sinks, filesystem boundaries, network destinations,
  approvals, and tool-chain depth

## Then — realistic agent coverage

- [ ] RAG and document-ingestion scenarios
- [ ] Memory and multi-turn attack scenarios
- [ ] Browser, code-execution, database, email, and MCP-style tool adapters
- [ ] Framework adapters that normalize into the same policy and trace boundary
- [ ] Cross-tenant and excessive-agency scenarios
- [ ] Independent benchmark comparison with clearly stated limitations

## Release maturity

- [ ] Stable Python API and schema compatibility policy
- [ ] Signed release artifacts, SBOM, and build provenance
- [ ] Pinned CI actions, dependency automation, and static analysis
- [ ] Maintainer and contribution governance
- [ ] Independent security review of the live integration boundary

Progress is tracked against the acceptance criteria in [GOALS.md](GOALS.md),
not by feature count alone.
