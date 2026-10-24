# Releasing AgentProbe

A maintainer runbook. Releases are built and published by
[`.github/workflows/release.yml`](../.github/workflows/release.yml) when a
version tag is pushed. Never build a release on a laptop and upload it: the
workflow is what produces the signed provenance that users verify.

## What the release workflow does

On a pushed `v*` tag, the `build` job:

1. checks that the tag equals `v` + `agentprobe.__version__`, and stops if not;
2. runs the test suite;
3. builds the sdist and wheel, runs `twine check --strict`, and audits the
   wheel's contents (`python -m research.public_hygiene --wheel`);
4. installs the wheel into a clean environment and records an SPDX SBOM of it
   and its resolved dependencies (kept as a workflow artifact named
   `agentprobe-security.spdx.json`);
5. creates a Sigstore-signed build-provenance attestation for the sdist and
   wheel, stored with the repository.

The `publish` job then uploads exactly those files to PyPI through trusted
publishing (no stored token), in the `pypi` environment. PEP 740 publish
attestations are uploaded with them.

## One-time setup

- **PyPI trusted publisher.** On pypi.org, Account, then Publishing: a
  publisher for project `agentprobe-security`, owner `nar1-frames`, repository
  `agentprobe`, workflow `release.yml`, environment `pypi`. Before the first
  release this is a "pending publisher".
- **GitHub environment.** Settings, then Environments: `pypi`. Add yourself as
  a required reviewer so every publish waits for your approval.
- **Tools.** The GitHub CLI (`gh`), logged in, for watching runs and verifying
  attestations.

## Where the version lives

Bump all of these together; `tests/test_action_gate.py` fails if the Action's
default drifts from the package version.

| File | What to change |
|---|---|
| `agentprobe/__init__.py` | `__version__` (the single source for the package) |
| `action/action.yml` | `inputs.package.default`: `agentprobe-security==X.Y.Z` |
| `action/README.md`, `action/examples/agentprobe.yml`, `README.md` | `nar1-frames/agentprobe/action@vX.Y.Z` |
| `SECURITY.md` | the version in the verification example |
| `CHANGELOG.md` | a `## [X.Y.Z] - YYYY-MM-DD` heading |

## Rehearse before tagging

Build from a clean export of the exact commit you will tag, so local files
that Git ignores cannot leak in:

```bash
REF=HEAD; VERSION=2.1.0
rm -rf /tmp/rehearsal && mkdir -p /tmp/rehearsal/src
git archive "$REF" | tar -x -C /tmp/rehearsal/src
cd /tmp/rehearsal/src && git init -q && git add -A   # the hygiene check reads the index
python -c 'import agentprobe; print(agentprobe.__version__)'   # must print $VERSION
python -m pytest -q
python -m build --outdir ../dist
python -m twine check --strict ../dist/*
python -m research.public_hygiene --wheel ../dist/*.whl
```

Run `actionlint` and `zizmor --offline .github/workflows/` too if a workflow
changed since the last release.

## Cut a release

```bash
VERSION=2.1.0
```

1. **Date the changelog.** In `CHANGELOG.md`, change the heading for
   `$VERSION` to today's date (`## [2.1.0] - 2026-10-30`). Commit and push, then
   wait for CI to go green:
   ```bash
   git commit -am "docs: date the $VERSION changelog entry"
   git push origin main
   ```
2. **Tag and push.**
   ```bash
   git tag -a "v$VERSION" -m "agentprobe-security $VERSION"
   git push origin "v$VERSION"
   ```
3. **Watch the release run**, and approve the `pypi` deployment when asked:
   ```bash
   gh run watch "$(gh run list --workflow release.yml --limit 1 --json databaseId -q '.[0].databaseId')"
   ```
4. **Verify the install** in a fresh environment:
   ```bash
   python -m venv /tmp/verify && /tmp/verify/bin/pip install "agentprobe-security==$VERSION"
   /tmp/verify/bin/agentprobe demo        # replays offline; prints the scan summary
   ```
5. **Verify provenance.** The attestation must verify against this repository:
   ```bash
   pip download "agentprobe-security==$VERSION" --no-deps -d check/
   gh attestation verify "check/agentprobe_security-$VERSION-py3-none-any.whl" \
     --repo nar1-frames/agentprobe
   ```
   Then check the links a user would follow:
   - `https://pypi.org/project/agentprobe-security/$VERSION/#files`: each file
     shows its provenance (the publish attestation from `release.yml`);
   - `https://github.com/nar1-frames/agentprobe/attestations`: the build
     attestation for both files;
   - the release run's artifacts: `agentprobe-security.spdx.json` (download it
     with `gh run download <run-id> -n agentprobe-security.spdx.json`).
6. **Publish the GitHub release** with notes written for a first-time reader:
   ```bash
   gh release create "v$VERSION" --verify-tag --title "agentprobe-security $VERSION" \
     --notes-file release-notes.md
   gh release upload "v$VERSION" agentprobe-security.spdx.json
   ```

## The first release: two tags

2.0.0 and 2.1.0 are both unreleased, so the first release pushes two tags in
order. Each tag publishes its own version.

1. Tag 2.0.0 at the commit that folded the 2.0.0 changes (`3cff4af`). Its
   `__version__` is `2.0.0`. Its changelog heading is not dated; that is
   expected, because the next step dates it on main.
   ```bash
   git tag -a v2.0.0 3cff4af -m "agentprobe-security 2.0.0"
   git push origin v2.0.0
   ```
   Approve the deployment and wait for the run to finish green.
2. On main, date both headings: `2.0.0` with the v2.0.0 tag date and `2.1.0`
   with today's date. Commit, push, and wait for CI.
3. Tag 2.1.0 at main and push it, as in "Cut a release", steps 2 to 6.

To give the 2.0.0 tag a dated heading instead, tag a one-commit branch:
`git switch -c release/2.0.0 3cff4af`, date the heading, commit, and tag that
commit in step 1.

## A patch release

A patch (`X.Y.Z+1`) carries only bug fixes, documentation, and
dependency-bound updates that do not change documented behaviour; see
[COMPATIBILITY.md](COMPATIBILITY.md#semantic-versioning).

- **If main holds only fixes since the last release:** bump the version
  everywhere in the table above, add the changelog entry, merge to main, and
  cut the release from main.
- **If main already holds unreleased features:** branch from the last tag,
  apply the fixes there, and release from the branch.
  ```bash
  git switch -c release/2.1.x v2.1.0
  git cherry-pick <fix-commit>...
  # bump the version to 2.1.1 everywhere in the table, add the changelog entry
  git commit -am "release: 2.1.1"
  git push origin release/2.1.x
  git tag -a v2.1.1 -m "agentprobe-security 2.1.1" && git push origin v2.1.1
  ```
  The release workflow runs for any `v*` tag, whatever branch it is on. Merge
  the changelog entry back to main afterwards.

## When something goes wrong

- **The tag check, tests, or build fail.** Nothing was published. Delete the
  tag, fix the problem on main, and tag again:
  `git tag -d "v$VERSION" && git push origin ":refs/tags/v$VERSION"`.
- **Publishing fails after the build** (for example, a misconfigured trusted
  publisher). Fix the PyPI or environment setting, then re-run only the failed
  job: `gh run rerun <run-id> --failed`. The same built files are published.
- **A broken release reached PyPI.** PyPI never accepts the same version
  twice, even after a deletion. Yank the release on pypi.org (Manage, then the
  release, then Yank) and publish a patch. Do not move or delete a tag after
  its files are on PyPI.
