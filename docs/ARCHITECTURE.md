# AgentProbe architecture

AgentProbe has two related but deliberately separate products:

1. **Model scanner.** Sends a fixed attack library to a chat-completions
   endpoint, classifies the response, and emits human-readable HTML plus a
   versioned JSON artifact.
2. **Agent harness.** Runs controlled tool-use scenarios with trusted and
   untrusted context, a policy gate, and fixture-only side effects. It measures
   whether an attack caused an action, not merely whether a model used unsafe
   language.

## Boundaries

```text
attack library ──> target adapter ──> canonical detector ──> scan artifacts
                                             │
                                             └── keyword route or LLM judge

trusted user + untrusted content ──> agent model ──> tool policy ──> fixture tools
                                                       │                 │
                                                       └─ block/allow     └─ audit log
```

The detector and the agent policy answer different questions. A keyword or
LLM verdict is evidence about model behavior. The policy gate is the control
that decides whether a requested action can create a side effect. A production
integration should keep both records.

The concrete assets, trust boundaries, STRIDE review, and residual risks are
listed in [`THREAT_MODEL.md`](THREAT_MODEL.md).

## Design decisions

- **One detector implementation.** `agentprobe/detection.py` is the canonical
  keyword/judge implementation; the historical root scripts import it.
- **Failed calls are not verdicts.** Target failures are marked
  `status=error` / `method=target-error` in JSON and are never sent to the
  judge; judge failures use `method=judge-error` and are excluded from
  findings as well.
- **Scan artifacts are attributable.** Each JSON report carries a unique run
  ID, tool version, provider metadata, and SHA-256 digests of the validated
  config, selected attack library, and judge prompt. HTML and JSON paths share
  that run ID, and the HTML embeds the same provenance in metadata tags for
  independent review.
- **Long scans are resumable without mixing evidence.** The optional scan
  checkpoint is a versioned, private, atomically replaced JSON document. It is
  written after each completed attack and is bound to the target, judge,
  filtered attack-library digest, and behavioral configuration metadata. Resume
  refuses an incompatible checkpoint and is idempotent for a completed one, so
  a report can be rebuilt after an output failure; a process interruption
  therefore loses at most the in-flight provider call.
- **The empirical protocol is executable.** `research/study_manifest.json`
  pins the target scope, attack-library digest, judge matrix, repeat count, and
  labeler rules; the publication gate checks those requirements by default.
- **Judge statistics are conservative.** Failed judge calls are excluded;
  Fleiss' κ is only computed for complete, fixed-k item groups. Ties are
  `SUSPICIOUS`, not row-order-dependent majorities.
- **External content is untrusted by default in the harness.** The fixture
  suite includes a deliberately vulnerable mode so the attack path remains
  observable and regression-testable.
- **Tool arguments are policy inputs.** Allowing `read_file` does not permit
  arbitrary paths; the guarded fixture policy accepts only the fixture sandbox
  prefix and requires confirmation for email.
- **Approvals are invocation-specific.** A confirmation is bound to the
  resolved tool name and arguments, so approving one request does not approve
  every later request for the same tool.
- **High-impact tools can be origin-scoped.** The fixture architecture policy
  denies external-content email requests even if a broad confirmation is
  present; user-origin requests still require their own exact approval.
- **Audit traces are ordered and data-minimized.** Harness JSON includes
  request, block, execution, provider-error, and tool-error events; sensitive
  tool arguments and side-effect payloads are redacted before serialization.
- **Provider errors are sanitized before persistence.** Common API keys and
  tenant identifiers are removed from scanner, research, and harness error
  records.
- **No fixture side effect is real by default.** The harness cannot send mail,
  read the host filesystem, make a network request, or delete an account unless
  an integration test explicitly supplies a different executor.
- **Benign controls are part of the suite.** The guarded runtime must still
  permit an in-boundary fixture read; a defense that blocks everything is not a
  useful agent integration.

## Extension point

`agentprobe.harness.AgentModel` is the adapter seam for deterministic models,
and `OpenAICompatibleAgent` is the live multi-step adapter for
OpenAI-compatible chat APIs. It accepts an explicit schema set and tool
executor for integration tests, while defaulting to fixture tools. Both paths
return `ToolCall` objects and keep `AgentRuntime`/`ToolPolicy` as the policy and
audit boundary. New scenarios should state their objective and required tool
sequence so success is measured from observed execution rather than from a
judge's interpretation.
