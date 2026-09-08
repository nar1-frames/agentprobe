# AgentProbe goals

AgentProbe is being built as an open-source security evaluation and enforcement
harness for LLM-powered agents.

## Product goals

1. **Make agent security testable.** Developers should be able to run realistic
   prompt-injection and tool-abuse scenarios locally, without connecting real
   accounts or creating real side effects.
2. **Measure outcomes, not appearances.** A model mentioning a tool is not the
   same as a tool executing. AgentProbe records requested, allowed, blocked, and
   executed actions separately.
3. **Make evidence reproducible.** Every scan and study artifact should identify
   its attack pack, configuration, provider settings, schema version, and run
   provenance.
4. **Keep the security boundary explicit.** Untrusted model output, retrieved
   documents, tool results, and external content must never gain authority just
   because they appear in a conversation.
5. **Be honest about uncertainty.** LLM judges are measurement tools, not ground
   truth. Human agreement, reliability, failure cases, and limitations belong in
   the result.

## Engineering goals

- A clean checkout should produce a useful offline result in under five minutes.
- The default harness must be network-free and side-effect-free.
- Every security regression gets a deterministic fixture and a test.
- The public Python API, CLI output schemas, and attack-pack format should be
  versioned before they are treated as stable.
- Releases should be inspectable, reproducible, and safe to install.

## Research goals

- Complete the preregistered v1.4 judge-validity and judge-reliability study.
- Report confidence intervals, disagreement cases, and limitations rather than
  only headline accuracy.
- Compare multiple judge configurations and, eventually, independent model
  families.
- Publish sanitized aggregate evidence only after privacy and provenance review.

## Non-goals

AgentProbe is not a guarantee that an agent is safe, a replacement for access
control, or permission to test systems without authorization. Model scanning is
evidence; policy enforcement and least privilege are the durable controls.
