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

- **One supported scanner path.** `agentprobe/scanner.py` owns provider
  construction, attack filtering, retries, checkpoints, and report emission;
  the installable CLI and interactive picker use it. The historical root
  scripts remain compatibility entry points, but are not the package's
  automation boundary.
- **One detector implementation.** `agentprobe/detection.py` is the canonical
  keyword/judge implementation used by the package scanner and compatibility
  scripts.
- **One provider boundary.** `agentprobe/providers.py` constructs the
  OpenAI-compatible clients used by the scanner and research collection,
  disables hidden SDK retries, and rejects malformed or missing custom
  endpoints before credentials or network calls are used.
- **Replay never fabricates.** `scan.record_replay_path` records every
  target and judge response under the SHA-256 of its canonical request, and
  the `replay` provider serves that file with no network or credentials. A
  request with no recorded entry raises `ReplayMiss`, which the scanner
  records as a target or judge error rather than a verdict (and
  `--fail-on-error` turns into a failing exit). A model missing from the
  recording fails preflight before the first attack is sent.
- **Failed calls are not verdicts.** Target failures are marked
  `status=error` / `method=target-error` in JSON and are never sent to the
  judge; judge failures use `method=judge-error` and are excluded from
  findings as well.
- **Scan artifacts are attributable.** Each JSON report carries a unique run
  ID, tool version, provider metadata, and SHA-256 digests of the validated
  config, selected attack library, and judge prompt. HTML and JSON paths share
  that run ID, and the HTML embeds the same provenance in metadata tags for
  independent review.
- **CI exports are data-minimized.** `--sarif` and `--junit` convert the
  versioned scan and harness reports for code scanning and CI test views.
  Those artifacts travel further than `reports/`, so they never contain target
  responses, judge reasoning, error strings, assistant messages, or tool
  traces. They carry attack IDs, categories, severities, verdicts, methods,
  statuses, and public attack-library text; an error row exports only its
  method (`target-error` or `judge-error`). SUSPICIOUS maps to SARIF
  `review`/`none`, because SARIF allows a non-`none` level only on `fail`.
- **Long scans are resumable without mixing evidence.** The optional scan
  checkpoint is a versioned, private, atomically replaced JSON document. It is
  written after each completed attack and is bound to the target, judge,
  filtered attack-library digest, and behavioral configuration metadata. Resume
  refuses an incompatible checkpoint and is idempotent for a completed one, so
  a report can be rebuilt after an output failure; a process interruption
  therefore loses at most the in-flight provider call. Explicit repair retries
  only target/judge-error rows; a judge-only repair reuses the frozen target
  response rather than silently sampling a replacement.
- **The empirical protocol is executable.** `research/study_manifest.json`
  pins the target scope, attack-library digest, judge matrix, repeat count, and
  labeler rules; the publication gate checks those requirements by default and
  reruns row-level dataset integrity validation before declaring readiness.
- **Attack packs layer oracles over a frozen library.** Each attack's success
  oracle lives in `attacks/oracles.py`, keyed by a stable `category-NN` ID;
  `agentprobe/attackpack.py` joins the oracles to `attacks/library.py` into a
  versioned, validated pack. The library dicts are never modified, so the
  `attack_library_sha256` pinned by the study manifest stays valid. Scan
  reports add `attack_pack_schema_version` and `attack_pack_sha256`, so a
  changed oracle shows up in provenance without changing the attack digest.
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
  present; unproven `live-model` email requests are denied by default as well,
  while user-origin requests still require their own exact approval.
- **Provider schemas and calls are input boundaries.** The live adapter rejects
  duplicate or malformed function schemas, invalid call IDs, and
  non-JSON-safe arguments before a policy or executor can see them.
- **Audit traces are ordered and data-minimized.** Harness JSON includes
  assistant messages plus request, block, execution, provider-error, and
  tool-error events; sensitive tool arguments, side-effect payloads, known
  tool-returned secrets, and copies of those secrets in assistant text are
  redacted before serialization.
- **Harness events are a closed, versioned vocabulary.** `agentprobe/events.py`
  registers every trace event the runtimes emit, with its required fields and
  the layer that produced it: model, tool, policy, execution, or content. Both
  runtimes build events through `make_event`, and serialization and harness
  reports refuse an unregistered or malformed event. Harness JSON carries
  `event_schema_version` alongside `schema_version`, so a consumer can tell
  which vocabulary a trace uses.
- **Live harness artifacts are attributable.** A live run records the target
  provider/model, token/step/temperature execution settings, a system-prompt digest, and a
  non-secret target-configuration digest without persisting the prompt or API
  key value.
- **Harness outcomes are explicit.** Required tool sequences are evaluated in
  order, and high-risk scenarios add an outcome predicate (such as the
  extracted secret reaching an email or a file path leaving the fixture
  boundary). A tool name appearing somewhere in a trace is not sufficient to
  claim that the malicious objective was reached.
- **Harness artifacts are durable evidence.** The CLI emits a versioned
  harness artifact with attack/control summaries and writes it atomically with
  private permissions; stdout JSON remains available for CI pipes.
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
OpenAI-compatible chat APIs. `agentprobe harness --live` exercises that adapter
against the configured target model while still defaulting to fixture tools;
it is opt-in because it makes provider calls. The adapter accepts an explicit
schema set and tool executor for integration tests, while defaulting to fixture
tools. Both paths return `ToolCall` objects and keep `AgentRuntime`/`ToolPolicy`
as the policy and audit boundary. New scenarios should state their objective
and required tool sequence so success is measured from observed execution
rather than from a judge's interpretation.
