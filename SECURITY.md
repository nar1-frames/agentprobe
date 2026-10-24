# Security policy

AgentProbe is a security testing instrument. Use it only against models and
systems you own or have explicit written permission to test.

## Safe testing

- Prefer local models or a provider-approved test environment.
- Do not point the automated scanner at a third-party production endpoint
  unless the program explicitly permits automated testing.
- Use the disclosure authorization gate before testing an external target.
- Keep real credentials in environment variables; never put them in YAML,
  reports, issues, or pull requests.
- Review model outputs and logs for sensitive data before sharing them.

The built-in agent harness uses in-memory fixture tools. It is safe to run
locally, but connecting it to real tools requires a separate least-privilege,
network-egress, authentication, and side-effect review.

## Verifying a release

Releases are built by `.github/workflows/release.yml` from a version tag, never
from a maintainer's machine. Each release records:

- a Sigstore-signed build-provenance attestation for the sdist and wheel,
  stored with the repository;
- PEP 740 publish attestations on PyPI, uploaded through trusted publishing;
- an SPDX SBOM of the installed package and its resolved dependencies, kept
  as a workflow artifact of the release run.

To check that a downloaded file came from this repository's release workflow:

```bash
pip download agentprobe-security==2.1.0 --no-deps -d check/
gh attestation verify check/agentprobe_security-2.1.0-py3-none-any.whl \
  --repo nar1-frames/agentprobe
```

## Reporting a vulnerability in this repository

Please avoid public disclosure of credentials, private model outputs, target
identifiers, or unpatched details. Open a private report through the repository
hosting service when available, or contact the maintainer through the profile
linked from the repository. Include a minimal reproduction, affected file or
version, and the security impact.

The empirical study data is not a substitute for a security report: its judge
and target artifacts may contain sensitive provider responses and must be
reviewed before redistribution.
