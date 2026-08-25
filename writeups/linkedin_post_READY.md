# LinkedIn post — paste-ready

Paste the text below the line into LinkedIn. Add the dev.to link once it's live
(replace [DEV.TO LINK]). Keep the repo link. First two lines are the "hook" that
shows before "…see more," so they matter most.

--------------------------------------------------------------------------------

I built an AI security scanner to test how easily language models fall for prompt-injection attacks — then found a bug in my own detection code. That bug taught me more than the tool did.

AgentProbe fires 49 known attack prompts (jailbreaks, data extraction, role-confusion, tool misuse) at a model and measures how often it complies. The hard part isn't the attack — it's detecting compliance, because models often *refuse in the first sentence and then comply in the next*.

My "cheap" detector for that pattern was quietly dead code: it returned a confidence score my own escalation logic ignored, so every case fell through to a slower LLM-as-judge. The feature looked like it worked only because the judge caught the same thing independently.

That sent me down a more interesting path: if an LLM is grading another LLM's safety, who's grading the judge? Three things I took away:

→ The judge has to be stronger than the model it judges, or they share blind spots (correlated errors).
→ Raw accuracy lies when one class dominates — use chance-corrected agreement (Cohen's kappa).
→ A judge should agree with itself across runs; when it flips, that's your signal for the genuinely ambiguous cases.

Next: turning the tool into a real experiment — measuring how often keyword matching and LLM-as-judge actually agree with a human, and where they don't.

Full write-up: [DEV.TO LINK]
Code (open source, defensive research): https://github.com/nar1-frames/agentprobe

#AI #Security #MachineLearning #LLM #Cybersecurity
