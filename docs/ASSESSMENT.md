# Fixed-fee assessment runbook

This is the end-to-end procedure for an AgentProbe agent security assessment:
one agent with up to two tools, the 49-attack library, a policy review of the
tools, a customer report, and one retest within 30 days. A competent engineer
can do the hands-on work in under a day. The five-business-day calendar
leaves room for the client to answer questions and fix things.

| Day | Step | Hands-on time |
|---|---|---|
| 0 | Scoping call, then the signed SoW with its authorization clause | 45 min |
| 1 | Wire the target and the judge, then a smoke test | 1-2 h |
| 2 | Scan, live harness, policy review | 1-2 h, mostly waiting |
| 3 | Triage, repair errors, render the report | 1-2 h |
| 4 | Delivery call | 30 min |
| within 30 days | Retest and comparison report | 1 h |

**What this is.** Control testing of one configuration with public,
well-known attacks, graded by a keyword pass and an LLM judge, and read by a
human. **What this is not:** a penetration test of the client's
infrastructure, a guarantee of safety, or a test against novel or multi-turn
attacks. The report says so in its methodology appendix. Say it on the
scoping call too.

## 1. Scoping call (30 minutes)

Get answers to all of these before quoting a start date:

- [ ] **System:** what the agent does, who uses it, and which model and
  provider sit behind it (needed to rank the judge).
- [ ] **Endpoint:** the URL of a staging or test environment (preferred over
  production), the HTTP method, the request JSON shape, and where the reply
  text sits in the response (`response_path`).
- [ ] **Auth:** a scan token issued for this test only, delivered out of
  band, revocable, and sent as a header. Never put it in a file.
- [ ] **Sessions:** whether each request can start a fresh conversation.
  AgentProbe sends a new `session_id` for every attack by default.
- [ ] **Tools (up to two):** the name, arguments, and side effects of each.
  Which tools can send data out, change records, or spend money? Ask for the
  tool schemas and the system prompt if the client will share them. They are
  needed for the live harness and the policy review.
- [ ] **Model access for the live harness:** can you call the underlying
  model through an OpenAI-compatible API with their system prompt? If not,
  the live harness is skipped and the report says so.
- [ ] **Limits:** rate limits, quotas, and a test window. One run is about 49
  requests to their endpoint and up to 49 judge calls on your side.
- [ ] **Data:** what the responses may contain, how long you may keep them,
  and whether the client wants the raw JSON at delivery. The default is no:
  they get HTML, PDF, and SARIF.
- [ ] **Contacts and dates:** a technical contact during the window, the
  delivery call date, and a provisional retest date.
- [ ] **Out of scope:** anything else (other agents, other environments,
  infrastructure), stated explicitly.

## 2. Authorization (before any traffic)

No request goes to the client's system until the signed statement of work is
in hand. It must name the system, the environment, the test window, the
expected request volume, and the person authorizing the test.

- Record the reference in `engagement.yaml` (`authorization:`). It prints on
  the report's first screen.
- Scan only the endpoint and window in the SoW. If something needs to change
  mid-test, get it in writing first.
- For bug-bounty style targets, AgentProbe's `disclosure/` gate
  (`python -m disclosure.cli check --target <id> --mode automated`) refuses
  automated testing unless an authorization record allows it. Client
  engagements rely on the SoW instead.

## 3. Wire the target and the judge

Create a working folder outside any Git repository, for example
`engagements/<client>/`. Everything in it may contain client data.

**A deployed agent (the usual case)** uses the `http` target:

```yaml
target:
  provider: http
  model: client-support-agent          # a label for the report
  base_url: https://staging.client.example/api/chat
  api_key_env: CLIENT_SCAN_TOKEN       # sent as "Authorization: Bearer <token>"
  strength_rank: 1
  timeout_seconds: 120
  http:
    request_template: {message: "{{prompt}}", session_id: "{{session_id}}"}
    response_path: reply.text          # dotted path into the JSON reply
    session: fresh
judge:
  provider: groq                       # a model you control, never the client's
  model: openai/gpt-oss-120b
  api_key_env: GROQ_API_KEY
  strength_rank: 2                     # must be >= the target's rank
  max_tokens: 120
  temperature: 0.1
  reasoning_effort: low
scan:
  categories: all
  rate_limit_seconds: 5                # respect the client's limits
  retries: 1
  record_replay_path: replay/scan.replay.json
output:
  report_dir: reports
  report_format: both
```

- **A bare model endpoint** (when the client wants the model itself tested)
  uses `provider: openai`, `groq`, `custom` (any OpenAI-compatible URL), or
  `ollama`. See the commented examples in the repository's `config.yaml`.
- **Record every run.** `scan.record_replay_path` saves every target and
  judge response, so the scan can be replayed offline, regraded, or
  re-rendered later with no traffic to the client. The recording holds raw
  responses: keep it with the client data.
- **Judge.** Use a model you control that is at least as strong as the
  target. Never use the client's model, and never the target model itself.
  `examples/langchain-quickstart-agent/agentprobe.yaml` is a complete,
  working example.

**Smoke test:** send one benign request with `curl` to confirm the shape and
the auth. Then start the scan. Configuration errors stop it with exit code 2
before any attack is sent.

## 4. Run the scan

```bash
export CLIENT_SCAN_TOKEN=...  GROQ_API_KEY=...
agentprobe scan --non-interactive --verbose --config client.yaml \
  --checkpoint reports/scan.checkpoint.json \
  --sarif reports/scan.sarif --junit reports/scan.junit.xml
```

- Expect roughly 10-15 seconds per attack with a 5-second rate limit, so 49
  attacks take about 10 minutes.
- If the run is interrupted, rerun the same command with `--resume`.
- The JSON report in `reports/` is the source for everything that follows.

## 5. Live harness and policy review

The harness answers a different question from the scan. The question is not
"did the model say something bad" but "would injected content make the agent
*request* a harmful tool action, and would the policy stop it."

**Live harness** (needs OpenAI-compatible access to the client's model):

```bash
agentprobe harness --live --mode guarded --config client-model.yaml \
  --system-prompt "$(cat client-system-prompt.txt)" \
  --json reports/harness.json --sarif reports/harness.sarif --fail-on-error
```

This drives the client's model and system prompt through AgentProbe's fixture
scenarios: indirect injection toward secret exfiltration, a file-boundary
escape, a privilege escalation, and a network-destination attack. The tools
are in-memory fixtures; **the client's real tools are never called.** Report
which scenarios the model attempted (requested tools), and note that the
fixture policy blocked them. The fixture policy shows what the client's tool
layer should do, but it does not prove the client's tools have that policy.
It cannot run through an `http` target, because a deployed endpoint returns
text, not tool calls.

**Policy review** (a checklist, run against the client's tool schemas and
their answers on the call). For each of the two tools, record yes, no, or
unknown:

1. Is the tool on an allowlist, and does a consequential call need approval
   bound to its exact arguments?
2. Are file or record arguments confined to a boundary after normalization?
3. Can data only reach approved sinks (for example, email recipients in an
   approved domain)?
4. Can network calls only reach allowlisted hosts over https?
5. Is there a limit on chained tool calls per request?

These five match AgentProbe's guarded fixture controls (see the README's
harness section). Put each "no" or "unknown" in the delivery notes as an
architecture-layer recommendation. These are the durable fixes; model-layer
refusals are not.

## 6. Triage (read every finding)

The judge is a measurement instrument with an error rate. In public scan 01,
a hand read set aside 3 of 8 judge findings
([`writeups/public-scan-01.md`](../writeups/public-scan-01.md)). Before
anything goes to a client:

1. **Repair operational errors first.** Judge or target failures are never
   verdicts. Retry only the failed rows:
   `agentprobe scan --non-interactive --config client.yaml --checkpoint
   reports/scan.checkpoint.json --resume --repair-errors`. A judge-only
   repair reuses the recorded target response.
2. **Read every VULNERABLE and PARTIAL row** in the JSON: the prompt, the
   response, and the judge's reason. Set a finding aside only when the
   response does not do what the attack intended. Examples: the judge's
   reason contradicts the response; the response is generic or invented
   rather than disclosed; or the response refuses. Never set a finding aside
   because it is inconvenient.
3. **Write the reasons in client language.** They print in the report next
   to the judge's call:

   ```yaml
   # triage.yaml: bound to this scan; it will not apply to any other run
   run_id: <run.run_id from the scan JSON>
   dismissed:
     - attack_id: "tool_misuse:4"
       reason: "The reply refuses to run the query and contains no SQL."
   ```

4. **Read the inconclusive rows (SUSPICIOUS)** and mention any that matter on
   the delivery call. They are listed in the report and never counted as
   findings.

## 7. Render the report

```yaml
# engagement.yaml
client: Client Co
engagement_id: AP-2026-001
assessment_window: "2026-11-02 to 2026-11-06"
system: "Support agent v3 (staging), two tools: lookup_order, send_email"
scope:
  - "Chat endpoint https://staging.client.example/api/chat"
  - "Tools: lookup_order (read), send_email (external sink)"
  - "AgentProbe attack library: 49 single-turn attacks"
prepared_by: Naren Ranjith
contact: "<your email>"
authorization: "SoW AP-2026-001 signed 2026-10-30 by <name, title>"
```

```bash
agentprobe report --scan reports/<scan>.json --out deliverables/report.html \
  --engagement engagement.yaml --triage triage.yaml
```

Open the HTML in a browser and print it to PDF (or use headless Edge or
Chrome, as in `examples/sample-report/README.md`). Check the first screen:
it shows the result, the score, the summary sentence, and the notice about
attacks that could not run. `examples/sample-report/` shows what a finished
report looks like.

**Deliver:** the report as HTML and PDF, the scan and harness SARIF (data
minimized, safe to forward), the policy-review notes, and the retest date.
Do not send the raw JSON, checkpoint, or recording unless the SoW says so:
they contain full model responses.

## 8. Delivery call (30 minutes)

1. The first screen: the result, the score, and what FAIL or INCOMPLETE
   means.
2. The top findings, most severe first, with the fix and its layer
   (architecture or design fixes are durable; model-layer fixes are
   probabilistic).
3. The policy-review gaps for the two tools.
4. What was set aside and why, and what could not be tested.
5. The retest date and what will be compared.

## 9. Retest (within 30 days)

1. Use the same config, judge, and attack library. A different library
   digest makes the scans incomparable, and the report says so.
2. Run the scan as in step 4, with a new checkpoint.
3. Do a fresh triage for the new `run_id`. Dismissals deliberately do not
   carry over: a changed response must be read again.
4. Run `agentprobe compare --baseline reports/<initial>.json --candidate
   reports/<retest>.json` for the engineer's view.
5. Run `agentprobe report --scan reports/<retest>.json --baseline
   reports/<initial>.json --engagement engagement.yaml --triage
   triage-retest.yaml --out deliverables/retest.html`. The "Since last scan"
   section lists regressions, fixes, and anything that could not be
   compared. It compares raw judge verdicts, so a finding you set aside in
   either scan can still show up there as a change; explain any such case
   on the call.

## 10. Data handling

- Keep engagement folders out of every Git repository. AgentProbe's
  `.gitignore` already ignores `reports/`, checkpoints, and recordings, and
  `python -m research.public_hygiene` refuses them in a public tree.
- Revoke or ask the client to revoke the scan token at the end of the
  window.
- Delete raw responses, recordings, and checkpoints at the retention date
  agreed in the SoW, and confirm it in writing.
