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

## Reporting a vulnerability in this repository

Please avoid public disclosure of credentials, private model outputs, target
identifiers, or unpatched details. Open a private report through the repository
hosting service when available, or contact the maintainer through the profile
linked from the repository. Include a minimal reproduction, affected file or
version, and the security impact.

The empirical study data is not a substitute for a security report: its judge
and target artifacts may contain sensitive provider responses and must be
reviewed before redistribution.
