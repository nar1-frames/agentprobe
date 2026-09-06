# AgentProbe threat model

This document defines the security boundary for the scanner and the agent
harness. AgentProbe is a testing instrument; it is not itself a general
purpose sandbox or an authorization service.

## Scope and authorization

The scanner is intended for models and endpoints that the operator owns or is
explicitly authorized to test. The default harness is safe to run locally
because its tools are fixtures and its side effects stay in memory. Connecting
the live adapter to a real tool implementation requires a separate review and
written authorization for that target.

## Assets

| Asset | Why it matters | Required property |
|---|---|---|
| Target responses | May contain sensitive prompts or model output | Do not publish without review |
| Judge prompts/responses | Determine reported findings | Preserve raw evidence and errors |
| Tool credentials | Could grant real-world authority | Never enter fixture traces or reports |
| Tool side effects | Email, files, accounts, or data | Must be policy-gated and auditable |
| Human labels | Ground truth for the empirical study | Keep independent from judge output |
| Disclosure records | Identify real targets and unpatched findings | Local-only and access-controlled |

## Trust boundaries and data flow

```text
operator config ──> validated scanner ──> target provider
                                      └──> judge provider

trusted user request + untrusted retrieved content
        └──> agent model ──> ToolPolicy ──> tool adapter ──> side effect
                                │
                                └──> audit trace
```

External model output, retrieved documents, email contents, and tool results
are data, not authority. Only the operator-controlled policy may authorize a
tool invocation.

## STRIDE-oriented threats

| Threat | Asset / boundary | Control | Residual risk |
|---|---|---|---|
| Spoofing | Fake system/admin instructions | Model behavior tests; no privilege from text alone | A model may still request an unsafe action |
| Tampering | Config and attack selection | YAML validation before client creation | Local filesystem permissions remain the operator's responsibility |
| Repudiation | Tool actions and disclosure workflow | Structured traces; disclosure history transitions | Logs are not remotely tamper-evident |
| Information disclosure | Secrets, files, system prompts | Fixture-only tools; tool allowlist; path rules; confirmation gates | Real integrations need their own data-loss controls |
| Denial of service | Provider calls and token spend | Timeouts, bounded retries, rate limits, max steps | Provider quotas and costs still apply |
| Elevation of privilege | Model-requested admin actions | Explicit allowlist and per-tool policy; no text-based role elevation | Policy configuration can still be too permissive |

## Security invariants

1. A target or judge failure is recorded as an operational error, never as a
   model finding.
2. A live model request never executes a tool without passing `ToolPolicy`.
3. Fixture tools never access the host filesystem, network, mail, or accounts.
4. Tool arguments are validated at the policy boundary, not trusted because a
   tool name was allowlisted.
5. High-impact tool policies may deny requests whose origin is untrusted
   external content, independent of a user confirmation.
6. Tool calls from the live model adapter are treated as unproven provenance;
   guarded high-impact email actions remain denied unless an integration
   supplies a separately reviewed provenance-aware policy.
7. Real credentials are read from environment variables, not YAML or reports.
8. Serialized harness traces redact secret-like tool arguments and side-effect
   payloads; provider error records redact common credentials and tenant IDs.
9. Publication analysis excludes incomplete and failed judge groups instead of
   imputing their verdicts.

## Out of scope

- Sandboxing arbitrary third-party tool implementations.
- Proving that a model is safe from all prompt injections.
- Production deployment authorization, identity, or secrets management.
- Treating the keyword detector or an LLM judge as ground truth.

Any production integration must add authentication, least-privilege service
accounts, network egress controls, secret isolation, rate limits, and an
independent review of the tool's side effects.
