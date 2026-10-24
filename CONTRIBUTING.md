# Contributing to AgentProbe

Thanks for helping improve an open-source security project. Contributions are
welcome in the scanner, agent harness, research tooling, documentation, and
attack library.

## Before opening a change

1. Read [SECURITY.md](SECURITY.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
2. For behavior changes, read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
3. Open an issue for a large feature or a new integration so the design can be
   discussed before implementation.

## Local setup

```bash
python3 -m pip install -e ".[dev]"
pytest
ruff check .
python scripts/check_links.py   # every relative link resolves (also run by pytest)
agentprobe harness --mode guarded
```

The default harness is offline and has no real side effects. Provider-backed
tests must be opt-in and must not require credentials for the normal test suite.

## Pull requests

Every pull request should explain:

- What changed and why.
- The security boundary affected.
- Tests added or updated.
- Any change to public output, configuration, or protocol schemas.
- Any new network call, secret-handling path, or external side effect.

New security behavior should include a deterministic regression test. New attack
cases should document their threat, severity, preconditions, expected safe
behavior, and success oracle.

Do not commit API keys, raw provider transcripts, private study packets,
checkpoints, or real engagement data. Use the existing ignored local artifact
paths for those files.

## Review standard

AgentProbe favors explicit boundaries over cleverness. A change that improves
model detection but weakens artifact privacy, tool authorization, or replay
behavior is not ready to merge.
